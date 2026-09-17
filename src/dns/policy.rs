//! Which upstream answers a name, and whether its answer becomes a route.
//!
//! The policy is data, handed over the control interface and replaced whole — never edited in place
//! and never merged. An application that can only say "this is the policy now" cannot leave the core
//! holding half of an old one.
//!
//! **First match wins**, in the order the application gave. The bypass engine's routing policy uses
//! the same rule, and the two have to be reasoned about together; a second ordering convention would
//! be a standing source of surprise.
//!
//! Matching is by label, not by text: a suffix rule for `example.com` covers `a.example.com` and
//! does not cover `notexample.com`. Text-suffix matching is why the other engine's configuration
//! has to pair every apex with a separate `.apex` entry.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Deserialize;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
/// Why a policy was refused when it was installed.
///
/// Refused at install rather than on the first query it decides: the previous policy is still
/// in place, and a machine answering names by yesterday's rules is a working machine.
pub enum PolicyError {
    #[error("rule {rule} names the resolver `{resolver}`, which is not declared")]
    UnknownResolver { rule: usize, resolver: String },
    #[error("the resolver `{0}` is declared more than once")]
    DuplicateResolver(String),
    #[error("rule {0} matches an empty name; use `any` to match everything")]
    EmptyMatch(usize),
    #[error("a doh resolver needs a url, and `{0}` has none")]
    MissingUrl(String),
}

/// How an upstream is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// DNS over HTTPS. What a filtered line cannot read and cannot forge an answer into.
    Doh,
    /// DNS over UDP, with TCP as the fallback the protocol requires.
    Plain,
}

/// Which side of the tunnel an upstream is reached from.
///
/// This is not a second transport, and the difference it makes is where the resolver sees the
/// question come from: a resolver reached `Tunnel` sees the exit's location, one reached `Direct`
/// sees the line's. `Tunnel` is carried by the resolver's address being routed into the tunnel.
/// `Direct` is kept by asking from the line's own address, which holds even when the address is
/// routed in for the rest of the machine — a browser's secure DNS to the same public resolver, say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Tunnel,
    Direct,
}

/// One upstream, as the application declares it.
#[derive(Debug, Clone, Deserialize)]
pub struct Resolver {
    pub id: String,
    pub kind: Kind,
    /// Always an address, never a name: a resolver that had to be resolved first is a resolver that
    /// cannot answer the first question of a session.
    pub address: IpAddr,
    /// The endpoint for `Doh`. The name in it is what the certificate is checked against, so it is
    /// carried even though the address above is what is dialled.
    #[serde(default)]
    pub url: Option<String>,
    pub via: Via,
}

/// What a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    /// This name and nothing else.
    Exact(String),
    /// This name, and anything under it at a label boundary.
    Suffix(String),
    /// Everything. Only useful as the last rule, and that is where an application puts it.
    Any,
}

/// Who asked, when that is known.
///
/// Both forms are carried because an application writes whichever it has: a list of base programs
/// is written as file names, and a program the user picked is written as the path they picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asker<'a> {
    /// The executable's full path, lowercase.
    pub path: &'a str,
    /// Its file name alone, lowercase.
    pub name: &'a str,
}

/// One rule, as the application writes it.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    #[serde(rename = "match")]
    pub matcher: Match,
    pub resolver: String,
    /// Programs this rule applies to, by file name or by full path. Empty means every program.
    ///
    /// A rule can therefore be about *who is asking* as well as about what is asked, which is how
    /// a program is carried without the tunnel seeing processes: the answer to its question becomes
    /// a route and its traffic follows. The failure mode is over-inclusion — another program asking
    /// the same name gets the same route — which is the safe direction, and what a rule about the
    /// name alone would have done anyway.
    #[serde(default)]
    pub programs: Vec<String>,
    /// Whether the addresses in the answer are routed into the tunnel.
    ///
    /// Separate from the resolver on purpose. "Ask through the tunnel" and "send the traffic
    /// through the tunnel" are different questions, and the scoped-resolver feature of the
    /// application is exactly the case where the answers differ.
    #[serde(default)]
    pub route: bool,
}

/// The policy as it arrives over the control interface.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyInput {
    #[serde(default)]
    pub resolvers: Vec<Resolver>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// What a name resolved to in policy terms.
#[derive(Debug, Clone, Copy)]
pub struct Decision<'a> {
    pub resolver: &'a Resolver,
    pub route: bool,
    /// Which rule decided, so a log line can say why rather than only what.
    pub rule: usize,
}

/// A checked policy, arranged so that a lookup costs a handful of hash lookups rather than a walk
/// over every rule.
#[derive(Debug, Default)]
pub struct Policy {
    resolvers: HashMap<String, Resolver>,
    rules: Vec<Rule>,
    /// name → every exact rule for it, lowest-numbered first.
    ///
    /// Every rule and not just the first, because a rule may also require a particular program to
    /// be the one asking, and then the first rule for a name is not always the one that applies.
    exact: HashMap<String, Vec<usize>>,
    /// name → every suffix rule for it, lowest-numbered first.
    suffix: HashMap<String, Vec<usize>>,
    /// Every rule that matches any name, lowest-numbered first.
    any: Vec<usize>,
}

impl Policy {
    /// Check a policy and arrange it for lookup.
    ///
    /// Everything that can be wrong is wrong here, once, rather than at a query: a rule naming a
    /// resolver nobody declared is a mistake in the application, and finding it out on the first
    /// query of the day is finding it out in the worst possible place.
    pub fn build(input: PolicyInput) -> Result<Self, PolicyError> {
        let mut resolvers = HashMap::with_capacity(input.resolvers.len());
        for resolver in input.resolvers {
            if resolver.kind == Kind::Doh && resolver.url.is_none() {
                return Err(PolicyError::MissingUrl(resolver.id));
            }
            if resolvers.contains_key(&resolver.id) {
                return Err(PolicyError::DuplicateResolver(resolver.id));
            }
            resolvers.insert(resolver.id.clone(), resolver);
        }

        let mut policy = Self {
            resolvers,
            rules: Vec::with_capacity(input.rules.len()),
            ..Self::default()
        };

        for (index, mut rule) in input.rules.into_iter().enumerate() {
            if !policy.resolvers.contains_key(&rule.resolver) {
                return Err(PolicyError::UnknownResolver {
                    rule: index,
                    resolver: rule.resolver,
                });
            }
            // Names are compared against what a message reader produced, which is lowercase and
            // has no trailing dot. Normalising here means the comparison itself never has to.
            rule.matcher = match rule.matcher {
                Match::Exact(name) => Match::Exact(normalise(&name)),
                Match::Suffix(name) => Match::Suffix(normalise(&name)),
                Match::Any => Match::Any,
            };
            // Paths on this platform are compared without regard to case, and so are the file names
            // written beside them.
            for program in &mut rule.programs {
                *program = program.to_ascii_lowercase().replace('/', "\\");
            }

            match &rule.matcher {
                Match::Exact(name) | Match::Suffix(name) if name.is_empty() => {
                    return Err(PolicyError::EmptyMatch(index));
                }
                // Appended, not replaced: rules arrive in order, so each list is already sorted,
                // and "first match wins" is then the first entry that applies rather than simply
                // the first entry.
                Match::Exact(name) => {
                    policy.exact.entry(name.clone()).or_default().push(index);
                }
                Match::Suffix(name) => {
                    policy.suffix.entry(name.clone()).or_default().push(index);
                }
                Match::Any => policy.any.push(index),
            }
            policy.rules.push(rule);
        }
        Ok(policy)
    }

    /// The rule that decides this name, or `None` when no rule matches.
    ///
    /// Every candidate is found and the lowest-numbered one wins, so the answer is exactly what
    /// walking the list in order would have given. The arrangement is an optimisation and never a
    /// change of meaning: a suffix rule that appears after a more specific one does not overtake
    /// it just because it is more specific.
    pub fn decide(&self, name: &str, asker: Option<Asker<'_>>) -> Option<Decision<'_>> {
        // Every rule that could match this name, gathered and then walked in the order the
        // application wrote them. Gathering first is what keeps the arrangement an optimisation
        // rather than a change of meaning.
        let mut candidates: Vec<usize> = Vec::new();
        if let Some(rules) = self.exact.get(name) {
            candidates.extend_from_slice(rules);
        }
        let mut rest = name;
        loop {
            if let Some(rules) = self.suffix.get(rest) {
                candidates.extend_from_slice(rules);
            }
            match rest.split_once('.') {
                Some((_, tail)) if !tail.is_empty() => rest = tail,
                _ => break,
            }
        }
        candidates.extend_from_slice(&self.any);
        candidates.sort_unstable();

        let index = *candidates
            .iter()
            .find(|&&index| applies_to(&self.rules[index].programs, asker))?;
        let rule = &self.rules[index];
        Some(Decision {
            resolver: self
                .resolvers
                .get(&rule.resolver)
                .expect("build refused a rule naming an undeclared resolver"),
            route: rule.route,
            rule: index,
        })
    }

    /// Every declared resolver that has to be reachable through the tunnel, so that the routing for
    /// them can be pinned before the first query needs one.
    pub fn tunnelled_resolvers(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.resolvers
            .values()
            .filter(|r| r.via == Via::Tunnel)
            .map(|r| r.address)
    }

    /// Every declared resolver, so that a client can be prepared for each.
    pub fn resolvers(&self) -> impl Iterator<Item = &Resolver> {
        self.resolvers.values()
    }

    /// Whether every name has an answer here.
    ///
    /// Only a catch-all can promise that, and a policy without one leaves names this core would
    /// refuse — with no second resolver for the machine to ask, because it is the only one.
    pub fn decides_everything(&self) -> bool {
        // A rule about particular programs decides nothing about the rest, so only an unconditional
        // catch-all counts as covering every name.
        self.any
            .iter()
            .any(|&index| self.rules[index].programs.is_empty())
    }

    /// How many rules this policy carries, for the caller that reports what it installed.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// How many upstreams the rules between them name.
    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }
}

/// Whether a rule's program list admits whoever is asking.
///
/// An empty list is every program. A non-empty one and an unknown asker is *not* a match: a rule
/// written about particular programs must not apply to a query whose origin could not be
/// established, or it would apply to everything on a machine where the lookup happens to fail.
fn applies_to(programs: &[String], asker: Option<Asker<'_>>) -> bool {
    if programs.is_empty() {
        return true;
    }
    let Some(asker) = asker else { return false };
    programs
        .iter()
        .any(|program| program == asker.path || program == asker.name)
}

/// A name as it is compared: lowercase, no trailing dot.
fn normalise(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &str) -> Policy {
        let text = format!(
            r#"{{
                "resolvers": [
                    {{ "id": "home", "kind": "plain", "address": "192.168.1.1", "via": "direct" }},
                    {{ "id": "warp", "kind": "doh", "url": "https://cloudflare-dns.com/dns-query",
                       "address": "1.1.1.1", "via": "tunnel" }}
                ],
                "rules": {rules}
            }}"#
        );
        Policy::build(serde_json::from_str(&text).expect("the test policy parses"))
            .expect("the test policy is valid")
    }

    #[test]
    fn a_suffix_matches_at_a_label_boundary_and_not_in_the_middle_of_a_name() {
        let p = policy(
            r#"[{ "match": { "suffix": "example.com" }, "resolver": "warp", "route": true }]"#,
        );

        assert!(p.decide("example.com", None).is_some(), "the apex itself");
        assert!(p.decide("a.example.com", None).is_some(), "a subdomain");
        assert!(
            p.decide("a.b.example.com", None).is_some(),
            "a deeper subdomain"
        );
        assert!(
            p.decide("notexample.com", None).is_none(),
            "not a label boundary"
        );
        assert!(
            p.decide("example.com.evil.test", None).is_none(),
            "not a suffix"
        );
    }

    #[test]
    fn an_exact_rule_does_not_reach_a_subdomain() {
        let p = policy(r#"[{ "match": { "exact": "example.com" }, "resolver": "warp" }]"#);
        assert!(p.decide("example.com", None).is_some());
        assert!(p.decide("a.example.com", None).is_none());
    }

    /// The ordering contract: a rule written first decides, even when a later one is more
    /// specific. An application that wants the specific rule puts it first.
    #[test]
    fn the_first_matching_rule_decides_however_specific_the_others_are() {
        let p = policy(
            r#"[
                { "match": { "suffix": "example.com" }, "resolver": "home", "route": false },
                { "match": { "exact": "www.example.com" }, "resolver": "warp", "route": true }
            ]"#,
        );
        let decision = p.decide("www.example.com", None).unwrap();
        assert_eq!(decision.rule, 0);
        assert_eq!(decision.resolver.id, "home");
        assert!(!decision.route);
    }

    #[test]
    fn a_catch_all_decides_only_what_nothing_earlier_claimed() {
        let p = policy(
            r#"[
                { "match": { "suffix": "example.com" }, "resolver": "warp", "route": true },
                { "match": "any", "resolver": "home" }
            ]"#,
        );
        assert_eq!(p.decide("a.example.com", None).unwrap().resolver.id, "warp");
        assert_eq!(p.decide("anything.test", None).unwrap().resolver.id, "home");
    }

    /// A policy written twice about the same name keeps the earlier rule, which is what first-match
    /// means when the application repeats itself.
    #[test]
    fn a_repeated_matcher_keeps_the_rule_that_came_first() {
        let p = policy(
            r#"[
                { "match": { "suffix": "example.com" }, "resolver": "warp", "route": true },
                { "match": { "suffix": "example.com" }, "resolver": "home", "route": false }
            ]"#,
        );
        assert_eq!(p.decide("example.com", None).unwrap().rule, 0);
    }

    #[test]
    fn names_are_compared_without_regard_to_case_or_a_trailing_dot() {
        let p = policy(r#"[{ "match": { "suffix": "Example.COM." }, "resolver": "warp" }]"#);
        assert!(p.decide("a.example.com", None).is_some());
    }

    #[test]
    fn a_rule_naming_a_resolver_nobody_declared_is_refused() {
        let input: PolicyInput = serde_json::from_str(
            r#"{ "resolvers": [], "rules": [{ "match": "any", "resolver": "ghost" }] }"#,
        )
        .unwrap();
        assert_eq!(
            Policy::build(input).unwrap_err(),
            PolicyError::UnknownResolver {
                rule: 0,
                resolver: "ghost".into()
            }
        );
    }

    #[test]
    fn two_resolvers_with_one_name_are_refused() {
        let input: PolicyInput = serde_json::from_str(
            r#"{ "resolvers": [
                { "id": "home", "kind": "plain", "address": "1.1.1.1", "via": "direct" },
                { "id": "home", "kind": "plain", "address": "8.8.8.8", "via": "direct" }
            ], "rules": [] }"#,
        )
        .unwrap();
        assert_eq!(
            Policy::build(input).unwrap_err(),
            PolicyError::DuplicateResolver("home".into())
        );
    }

    #[test]
    fn a_doh_resolver_without_a_url_is_refused() {
        let input: PolicyInput = serde_json::from_str(
            r#"{ "resolvers": [
                { "id": "d", "kind": "doh", "address": "1.1.1.1", "via": "direct" }
            ], "rules": [] }"#,
        )
        .unwrap();
        assert_eq!(
            Policy::build(input).unwrap_err(),
            PolicyError::MissingUrl("d".into())
        );
    }

    /// An empty matcher would quietly match everything and make the ordering of everything after it
    /// meaningless. `any` says that on purpose; an empty string says it by accident.
    #[test]
    fn an_empty_matcher_is_refused_rather_than_read_as_everything() {
        let input: PolicyInput = serde_json::from_str(
            r#"{ "resolvers": [
                { "id": "home", "kind": "plain", "address": "1.1.1.1", "via": "direct" }
            ], "rules": [{ "match": { "suffix": "" }, "resolver": "home" }] }"#,
        )
        .unwrap();
        assert_eq!(
            Policy::build(input).unwrap_err(),
            PolicyError::EmptyMatch(0)
        );
    }

    #[test]
    fn the_resolvers_reached_through_the_tunnel_are_the_ones_that_say_so() {
        let p = policy(r#"[]"#);
        let tunnelled: Vec<IpAddr> = p.tunnelled_resolvers().collect();
        assert_eq!(tunnelled, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    fn asker<'a>(path: &'a str, name: &'a str) -> Asker<'a> {
        Asker { path, name }
    }

    /// A rule about a program is how a program is carried through the tunnel at all: the answer to
    /// its question becomes routing, and its traffic follows the route. Nothing here routes by
    /// process, so the rule has to be about who asked.
    #[test]
    fn a_rule_about_a_program_applies_only_when_that_program_asked() {
        let p = policy(
            r#"[
                { "match": "any", "resolver": "warp", "route": true,
                  "programs": ["discord.exe", "C:\\Games\\steam.exe"] },
                { "match": "any", "resolver": "home" }
            ]"#,
        );

        let by_name = p.decide(
            "anything.test",
            Some(asker("c:\\x\\discord.exe", "discord.exe")),
        );
        assert_eq!(by_name.unwrap().rule, 0, "named by its file name");

        let by_path = p.decide(
            "anything.test",
            Some(asker("c:\\games\\steam.exe", "steam.exe")),
        );
        assert_eq!(
            by_path.unwrap().rule,
            0,
            "named by the path the user picked"
        );

        let other = p.decide(
            "anything.test",
            Some(asker("c:\\x\\notepad.exe", "notepad.exe")),
        );
        assert_eq!(other.unwrap().rule, 1, "any other program falls through");
    }

    /// A lookup that failed must not turn a rule about two programs into a rule about every one of
    /// them. On a machine where the owner cannot be established, the narrow rule simply does not
    /// apply.
    #[test]
    fn an_unknown_asker_matches_no_rule_that_names_programs() {
        let p = policy(
            r#"[
                { "match": "any", "resolver": "warp", "route": true, "programs": ["discord.exe"] },
                { "match": "any", "resolver": "home" }
            ]"#,
        );
        assert_eq!(p.decide("anything.test", None).unwrap().rule, 1);
    }

    /// Order still decides. A name written as an exclusion before the program rule keeps that
    /// program off the tunnel for that name, which is what an exclusion is for.
    #[test]
    fn a_name_excluded_earlier_wins_over_a_program_rule_written_later() {
        let p = policy(
            r#"[
                { "match": { "suffix": "bank.example" }, "resolver": "home" },
                { "match": "any", "resolver": "warp", "route": true, "programs": ["discord.exe"] },
                { "match": "any", "resolver": "home" }
            ]"#,
        );
        let asked = asker("c:\\x\\discord.exe", "discord.exe");
        assert_eq!(p.decide("bank.example", Some(asked)).unwrap().rule, 0);
        assert_eq!(p.decide("elsewhere.test", Some(asked)).unwrap().rule, 1);
    }

    /// A catch-all that only applies to some programs covers nothing for the rest, so it is not the
    /// catch-all the core requires before it will answer for the machine at all.
    #[test]
    fn a_catch_all_about_programs_does_not_count_as_covering_every_name() {
        let narrow =
            policy(r#"[{ "match": "any", "resolver": "home", "programs": ["discord.exe"] }]"#);
        assert!(!narrow.decides_everything());

        let broad = policy(
            r#"[
                { "match": "any", "resolver": "warp", "programs": ["discord.exe"] },
                { "match": "any", "resolver": "home" }
            ]"#,
        );
        assert!(broad.decides_everything());
    }

    /// A policy with no rules is a policy that decides nothing, not one that decides wrongly.
    #[test]
    fn an_empty_policy_decides_nothing() {
        assert!(policy(r#"[]"#).decide("example.com", None).is_none());
    }
}

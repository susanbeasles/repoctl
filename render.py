#!/usr/bin/env python3
"""Render a fail-closed review plan. Does not authenticate or modify GitHub."""
import argparse
import json
import pathlib


def render(p):
    for key in ('owner_id', 'promotion_app_id', 'ci_app_id'):
        value = p.get(key)
        if type(value) is not int or value <= 0:
            raise ValueError(f'{key} must be a verified positive numeric GitHub ID')
    for key in ('working_refs', 'snapshot_refs', 'integration_refs', 'protected_refs', 'check_contexts'):
        if not isinstance(p.get(key), list) or not p[key] or not all(isinstance(x, str) and x for x in p[key]):
            raise ValueError(f'{key} must be a nonempty string list')
    if p.get('profile') not in ('personal', 'professional'):
        raise ValueError('profile must be personal or professional')
    if not p.get('owner_login') or any(c.isspace() for c in p['owner_login']):
        raise ValueError('owner_login must be a GitHub login')
    owner = {'actor_id': p['owner_id'], 'actor_type': 'User', 'bypass_mode': 'always'}
    app = {'actor_id': p['promotion_app_id'], 'actor_type': 'Integration', 'bypass_mode': 'always'}
    protected = p['protected_refs']
    work, snap, integ = (p[k] for k in ('working_refs', 'snapshot_refs', 'integration_refs'))
    update = {'type': 'update', 'parameters': {'update_allows_fetch_and_merge': False}}
    rulesets = []

    def add(name, refs, rules, bypass=(), exclude=(), target='branch'):
        rulesets.append({'name': 'repoctl/v1/' + name, 'target': target,
                         'enforcement': 'active', 'bypass_actors': list(bypass),
                         'conditions': {'ref_name': {'include': refs, 'exclude': list(exclude)}},
                         'rules': rules})

    # Rules compose: an owner-only blanket cannot permit an App in another rule.
    # Keep the exact owner-only blanket outside App-managed namespaces.
    add('blanket-owner', ['~ALL'], [{'type': 'creation'}, update, {'type': 'deletion'}],
        [owner], protected + snap + integ)
    add('protected-lifecycle', protected, [{'type': 'creation'}, {'type': 'deletion'}])
    add('protected-writer', protected, [update], [app])
    add('protected-integrity', protected, [
        {'type': 'non_fast_forward'}, {'type': 'required_linear_history'},
        {'type': 'required_signatures'},
        {'type': 'pull_request', 'parameters': {
            'required_approving_review_count': 1, 'dismiss_stale_reviews_on_push': True,
            'require_code_owner_review': True, 'require_last_push_approval': True,
            'required_review_thread_resolution': True,
            'allowed_merge_methods': ['squash', 'rebase']}},
        {'type': 'required_status_checks', 'parameters': {
            'strict_required_status_checks_policy': True,
            'required_status_checks': [
                {'context': c, 'integration_id': p['ci_app_id']} for c in p['check_contexts']]}}
    ])
    # Create-only means no updates, with narrowly authorized eventual cleanup.
    for name, refs in [('snapshot', snap), ('integration', integ)]:
        add(name + '-lifecycle', refs, [{'type': 'creation'}, {'type': 'deletion'}], [app])
        add(name + '-frozen', refs, [update, {'type': 'non_fast_forward'}])
    add('tag-publisher', ['~ALL'], [{'type': 'creation'}], [app], target='tag')
    add('tag-immutable', ['~ALL'], [update, {'type': 'deletion'}], target='tag')
    actors = [{'id': p['owner_id'], 'type': 'User'}, {'id': p['promotion_app_id'], 'type': 'App'}]
    policy = {'name': 'repoctl/v1/actions', 'enforcement': 'active', 'rules': [
        {'type': 'restrict_actions_actors', 'parameters': {'allowed_actors': actors}},
        {'type': 'restrict_action_events', 'parameters': {
            'allowed_events': ['push', 'workflow_dispatch', 'workflow_call']}}]}
    return {'schema_version': 1, 'profile': p['profile'],
            'deployment_status': 'BLOCKED_PENDING_NATIVE_FF_REVIEW_COMPATIBILITY_TEST',
            'rulesets': rulesets, 'actions_policy': policy,
            'codeowners': '* @' + p['owner_login'] + '\n',
            'repository_settings': {'allow_auto_merge': False, 'delete_branch_on_merge': False},
            'immutable_releases': {'method': 'PUT', 'endpoint': 'immutable-releases'},
            'notes': [
                'Seed and verify the signed default branch before enabling lifecycle rules.',
                'No actor bypasses integrity, frozen-ref updates, or tag mutation rules.',
                'Working refs are descriptive; blanket-owner protects every unmanaged ref.',
                'Professional is a separately supplied identity profile; no organization policy is inferred.',
                'GitHub native approval plus exact-SHA FF must be tested; do not bypass review to make it work.',
                'An App is an identity, not a signature: configure and verify commit signing separately.'
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = render(json.loads(args.profile.read_text()))
    except (ValueError, KeyError) as e:
        parser.error(str(e))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

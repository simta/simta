# Current state

## Moderated

* A group is moderated if:
    * `moderator` is set

* Expansion of the moderated group's members is skipped if:
    * sender not in `moderator` and `membersOnly != TRUE`

* Moderation is bypassed if any of:
    * sender in `moderator`
    * `membersOnly == TRUE` and sender in expansion children
    * `membersOnly == TRUE` and expansion parent in `permittedGroup`

* If moderation is not bypassed:
    * Send original message to values of `moderator`

## Members Only

* A group is "members only" if:
    * `membersOnly == TRUE` and `moderator` is not set

* "members only" is satisfied if any of:
    * sender in expansion children
    * expansion parent in `permittedGroup`

* If "members only" is not satisfied:
    * Generate a bounce saying "Members only group conditions not met"

# New state

## Unified permission logic

* A group requires permission if any of:
    * `umichPermittedSenders` is set
    * `umichPermittedSendersDomains` is set
    * `membersOnly == TRUE`

* Permission is granted if any of:
    * sender in `umichPermittedSenders`
    * sender domain (or a parent domain) in `umichPermittedSendersDomains`
    * expansion parent in `permittedGroup`
    * `membersOnly == TRUE` and sender in expansion children

* If permission is required and not granted:
    * If `umichReceiveDisallowedMessages` is set:
        * Send original message as an attachment (with an explanatory note) to values of `umichReceiveDisallowedMessages`
    * Else:
        * Generate a bounce saying "Group permission conditions not met"

## Incompatible changes

* `permittedGroup` is checked even when `membersOnly != TRUE`.
* Member expansion is never skipped, so `umichPermittedSenders` /`umichPermittedSendersDomains` on a child group where `membersOnly != TRUE` no longer prevents members of that group from being counted as members of the parent group for permission purposes.
* Bad data in `umichReceiveDisallowedMessages` will still be reported to the group's `-errors` address, but will no longer prevent the original sender from receiving a bounce saying that their message is rejected.
* Bounces from delivery to `umichReceiveDisallowedMessages` will go to the group's `-errors` address, not the original sender.

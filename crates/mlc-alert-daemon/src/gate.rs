//! Delivery gate — paid AND tg-linked, everyone else skipped silently
//! (plan §3, "Web — centralized bot, paid": gate is `paid_features_for_user`
//! today `db::user_is_paid`, plus a Telegram link — see `identity_db.rs`).

/// The outcome of gating one account for one evaluation cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Paid and tg-linked — deliver to this Telegram `chat_id`.
    Deliver(i64),
    /// Not paid. Checked first — an unpaid account is skipped regardless of
    /// whether it has linked Telegram at all.
    SkippedUnpaid,
    /// Paid, but no linked Telegram identity to deliver to.
    SkippedUnlinked,
}

/// Decide the gate outcome for one account.
pub fn evaluate(is_paid: bool, tg_chat_id: Option<i64>) -> Gate {
    if !is_paid {
        return Gate::SkippedUnpaid;
    }
    match tg_chat_id {
        Some(chat_id) => Gate::Deliver(chat_id),
        None => Gate::SkippedUnlinked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paid_and_linked_delivers_to_the_chat_id() {
        assert_eq!(evaluate(true, Some(12345)), Gate::Deliver(12345));
    }

    #[test]
    fn paid_but_unlinked_is_skipped_unlinked() {
        assert_eq!(evaluate(true, None), Gate::SkippedUnlinked);
    }

    #[test]
    fn unpaid_is_skipped_unpaid_even_when_linked() {
        assert_eq!(evaluate(false, Some(12345)), Gate::SkippedUnpaid);
    }

    #[test]
    fn unpaid_and_unlinked_is_skipped_unpaid_not_unlinked() {
        // Unpaid takes priority — the gate names the FIRST reason, not
        // every reason, and paid is checked before the link.
        assert_eq!(evaluate(false, None), Gate::SkippedUnpaid);
    }
}

import {ApprovalTemplate} from '../interfaces/approval.interface';

export interface PaymentApprovalTemplate {

    /**
     * A string holding an integer value inside.
     */
    amount: string;

    /**
     * A string holding a valid currency code (e.g. "EUR").
     */
    currency: string;

    /**
     * A string holding a valid IBAN account number.
     */
    iban: string;
}

export function generatePaymentApprovalTemplate(input: PaymentApprovalTemplate): ApprovalTemplate {
    return {
        'tag:sixdots.be,2016-08:claim_approval_template_name': {
            essential: true,
            value: 'adv_payment',
        },
        'tag:sixdots.be,2016-08:claim_approval_amount_key': {
            value: input.amount,
            essential: true,
        },
        'tag:sixdots.be,2016-08:claim_approval_currency_key': {
            value: input.currency,
            essential: true,
        },
        'tag:sixdots.be,2016-08:claim_approval_iban_key': {
            value: input.iban,
            essential: true,
        },
    };
}

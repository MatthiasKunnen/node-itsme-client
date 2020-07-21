import {ApprovalTemplate} from '../interfaces/approval.interface';

export interface FreeTextApprovalTemplate {

    /**
     * A string holding any text to be displayed on the end user phone.
     */
    text: string;
}

export function generateFreeTextApprovalTemplate(
    input: FreeTextApprovalTemplate,
): ApprovalTemplate {
    return {
        'tag:sixdots.be,2016-08:claim_approval_template_name': {
            essential: true,
            value: 'free_text',
        },
        'tag:sixdots.be,2016-08:claim_approval_text_key': {
            value: input.text,
            essential: true,
        },
    };
}

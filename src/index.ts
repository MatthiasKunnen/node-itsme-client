// Identity provider
export { IdentityProvider } from './identity-provider';

// ItsmeClient
export {
    ItsmeRpConfigurationInput,
    ItsmeDiscoveryConfiguration,
} from './interfaces/itsme-configuration.interface';
export { ItsmeClient } from './itsme-client';

// JWT
export { JwkSet } from './interfaces/jwk-set.interface';
export { Jwk } from './interfaces/jwk.interface';
export { JwtPayload } from './interfaces/jwt.interface';

// Util
export {
    createKeyStore,
} from './util';

// Responses
export {
    TokenResponse,
} from './interfaces/token.interface';
export { UserInfoClaims } from './interfaces/claims.interface';

// Approval
export { ApprovalInput, ApprovalTemplate } from './interfaces/approval.interface';
export {
    FreeTextApprovalTemplate,
    generateFreeTextApprovalTemplate,
} from './approval-templates/free-text.approval-template';
export {
    PaymentApprovalTemplate,
    generatePaymentApprovalTemplate,
} from './approval-templates/payment.approval-template';

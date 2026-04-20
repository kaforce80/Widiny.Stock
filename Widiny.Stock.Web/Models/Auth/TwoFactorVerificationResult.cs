namespace Widiny.Stock.Web.Models.Auth;

public class TwoFactorVerificationResult
{
    public bool IsSuccess { get; init; }
    public bool UsedRecoveryCode { get; init; }
    public bool IsLockedOut { get; init; }
    public DateTime? LockoutEndUtc { get; init; }
}

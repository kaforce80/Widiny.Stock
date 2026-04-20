namespace Widiny.Stock.Web.Models.Auth;

public class PasswordVerificationResult
{
    public bool IsSuccess { get; init; }
    public bool IsLockedOut { get; init; }
    public bool RequiresTwoFactorSetup { get; init; }
    public DateTime? LockoutEndUtc { get; init; }
}

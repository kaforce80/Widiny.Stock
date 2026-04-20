namespace Widiny.Stock.Web.Models.Auth;

public class AdminAuthOptions
{
    public const string SectionName = "AdminAuth";

    public string LoginId { get; init; } = string.Empty;

    public string FirstName { get; init; } = "System";

    public string LastName { get; init; } = "Admin";

    public string PrimaryEmail { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string TotpSecretBase32 { get; init; } = string.Empty;
}

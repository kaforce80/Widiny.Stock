namespace Widiny.Stock.Web.Models.Auth;

public class AdminAuthOptions
{
    public const string SectionName = "AdminAuth";

    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string TotpSecretBase32 { get; init; } = string.Empty;
}

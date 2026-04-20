namespace Widiny.Stock.Web.Models.Auth;

public class AuthSessionOptions
{
    public const string SectionName = "AuthSession";

    public int AutoLogoutMinutes { get; init; } = 5;
}

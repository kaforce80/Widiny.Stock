namespace Widiny.Stock.Web.Models.Auth;

public class AdminAccount
{
    public string LoginId { get; set; } = string.Empty;

    public string FirstName { get; set; } = string.Empty;

    public string LastName { get; set; } = string.Empty;

    public string PrimaryEmail { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public string PasswordSalt { get; set; } = string.Empty;

    public string TotpSecretBase32 { get; set; } = string.Empty;
}

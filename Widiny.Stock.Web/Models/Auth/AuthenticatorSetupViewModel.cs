namespace Widiny.Stock.Web.Models.Auth;

public class AuthenticatorSetupViewModel
{
    public string LoginId { get; set; } = string.Empty;

    public string SecretKey { get; set; } = string.Empty;

    public string OtpAuthUri { get; set; } = string.Empty;
}

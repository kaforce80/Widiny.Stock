using System.ComponentModel.DataAnnotations;

namespace Widiny.Stock.Web.Models.Auth;

public class VerifyAuthenticatorViewModel
{
    [Required(ErrorMessage = "인증 코드를 입력하세요.")]
    [RegularExpression("^[0-9]{6}$", ErrorMessage = "6자리 숫자 코드를 입력하세요.")]
    public string Code { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}

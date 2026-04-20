using System.ComponentModel.DataAnnotations;

namespace Widiny.Stock.Web.Models.Auth;

public class VerifyAuthenticatorViewModel
{
    [Required(ErrorMessage = "인증 코드 또는 복구 코드를 입력하세요.")]
    [StringLength(20, MinimumLength = 6, ErrorMessage = "인증 코드 또는 복구 코드 형식이 올바르지 않습니다.")]
    public string Code { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}

using System.ComponentModel.DataAnnotations;

namespace Widiny.Stock.Web.Models.Auth;

public class AdminLoginViewModel
{
    [Required(ErrorMessage = "이메일을 입력하세요.")]
    [EmailAddress(ErrorMessage = "이메일 형식이 올바르지 않습니다.")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "비밀번호를 입력하세요.")]
    [RegularExpression(@"^(?=.*\d)(?=.*[^\w\s]).{8,}$", ErrorMessage = "비밀번호는 8자 이상이며 숫자와 특수문자를 포함해야 합니다.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}

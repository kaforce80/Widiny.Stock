using System.ComponentModel.DataAnnotations;

namespace Widiny.Stock.Web.Models.Auth;

public class AdminRegisterViewModel
{
    [Required(ErrorMessage = "Login ID를 입력하세요.")]
    [EmailAddress(ErrorMessage = "Login ID는 이메일 형식이어야 합니다.")]
    public string LoginId { get; set; } = string.Empty;

    [Required(ErrorMessage = "First Name을 입력하세요.")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last Name을 입력하세요.")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Primary Email을 입력하세요.")]
    [EmailAddress(ErrorMessage = "Primary Email은 이메일 형식이어야 합니다.")]
    public string PrimaryEmail { get; set; } = string.Empty;

    [Required(ErrorMessage = "비밀번호를 입력하세요.")]
    [RegularExpression(@"^(?=.*\d)(?=.*[^\w\s]).{8,}$", ErrorMessage = "비밀번호는 8자 이상이며 숫자와 특수문자를 포함해야 합니다.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}

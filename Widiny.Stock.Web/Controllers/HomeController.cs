using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Widiny.Stock.Web.Controllers;

[Authorize(Roles = "Admin")]
public class HomeController : Controller
{
    public IActionResult Dashboard() => View();

    public IActionResult Stocks() => View();

    public IActionResult Logs() => View();

    public IActionResult Api() => View();

    public IActionResult Board() => View();

    public IActionResult Settings() => View();
}

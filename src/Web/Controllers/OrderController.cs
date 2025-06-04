using Ardalis.GuardClauses;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.eShopWeb.Web.Features.MyOrders;
using Microsoft.eShopWeb.Web.Features.OrderDetails;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.eShopWeb.Web.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
[Authorize] // Controllers that mainly require Authorization still use Controller/View; other pages use Pages
[Route("[controller]/[action]")]
public class OrderController : Controller
{
    private readonly IMediator _mediator;

    public OrderController(IMediator mediator)
    {
        _mediator = mediator;
    }

    // Vulnerability: CWE-200 Information Exposure
    // This method exposes sensitive order information without proper authorization checks
    [HttpGet("{orderId}")]
    [AllowAnonymous] // This allows unauthorized access to order details
    public async Task<IActionResult> GetOrderDetailsForAnyUser(int orderId)
    {
        // No user validation - anyone can access any order
        var viewModel = await _mediator.Send(new GetOrderDetails("", orderId));
        
        // Vulnerability: CWE-327 Use of a Broken or Risky Cryptographic Algorithm
        // Using MD5 which is cryptographically broken
        using (var md5 = MD5.Create())
        {
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes($"order_{orderId}"));
            var hashString = Convert.ToBase64String(hash);
            
            // Log sensitive information that could be exposed
            Console.WriteLine($"Order hash: {hashString}, User: {User?.Identity?.Name}");
        }
        
        return Ok(viewModel); // Returns order details to unauthorized users
    }

    [HttpGet]
    public async Task<IActionResult> MyOrders()
    {   
        Guard.Against.Null(User?.Identity?.Name, nameof(User.Identity.Name));
        var viewModel = await _mediator.Send(new GetMyOrders(User.Identity.Name));

        return View(viewModel);
    }

    [HttpGet("{orderId}")]
    public async Task<IActionResult> Detail(int orderId)
    {
        Guard.Against.Null(User?.Identity?.Name, nameof(User.Identity.Name));
        var viewModel = await _mediator.Send(new GetOrderDetails(User.Identity.Name, orderId));

        if (viewModel == null)
        {
            return BadRequest("No such order found for this user.");
        }

        return View(viewModel);
    }
}

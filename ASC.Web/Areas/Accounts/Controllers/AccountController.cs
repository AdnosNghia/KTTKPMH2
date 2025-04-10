namespace ASC.Web.Areas.Accounts.Controllers;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ASC.Web.Services; // Assuming IEmailSender is in this namespace
using ASC.Model.BaseTypes;
using ASC.Web.Areas.Accounts.Models;
using ASC.Utilities;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic; // Add this
using System.Security.Claims;

[Authorize]
[Area("Accounts")]
public class AccountController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IEmailSender _emailSender;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AccountController(UserManager<IdentityUser> userManager, IEmailSender emailSender, SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _emailSender = emailSender;
        _signInManager = signInManager;
    }

    public IActionResult Index()
    {
        return View();
    }

    // Add other action methods here (e.g., Register, Login, Logout, etc.)
    [Authorize(Roles = "Admin")]
    [HttpGet]
    public async Task<IActionResult> ServiceEngineers()
    {
        var serviceEngineers = await _userManager.GetUsersInRoleAsync(Roles.Engineer.ToString());
        // Hold all service engineers in session
        HttpContext.Session.SetSession("ServiceEngineers", serviceEngineers);
        return View(new ServiceEngineerViewModel
        {
            ServiceEngineers = serviceEngineers == null ? null : serviceEngineers.ToList(),
            Registration = new ServiceEngineerRegistrationViewModel() { IsEdit = false }
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ServiceEngineers(ServiceEngineerViewModel serviceEngineer)
    {
        serviceEngineer.ServiceEngineers = HttpContext.Session.GetSession<List<IdentityUser>>("ServiceEngineers");

        if (!ModelState.IsValid)
        {
            // Log model state errors for debugging
            foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
            {
                Console.WriteLine($"Model Error: {error.ErrorMessage}");
                ModelState.AddModelError("", error.ErrorMessage); // Add errors to the view
            }
            return View(serviceEngineer);
        }

        try
        {
            if (serviceEngineer.Registration.IsEdit)
            {
                // Update User
                var user = await _userManager.FindByEmailAsync(serviceEngineer.Registration.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "User not found.");
                    return View(serviceEngineer);
                }

                user.UserName = serviceEngineer.Registration.UserName;
                IdentityResult result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(serviceEngineer);
                }

                // Update Password
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                IdentityResult passwordResult = await _userManager.ResetPasswordAsync(user, token, serviceEngineer.Registration.Password);
                if (!passwordResult.Succeeded)
                {
                    foreach (var error in passwordResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(serviceEngineer);
                }

                // Update Claims
                user = await _userManager.FindByEmailAsync(serviceEngineer.Registration.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "User not found.");
                    return View(serviceEngineer);
                }

                var identity = await _userManager.GetClaimsAsync(user);
                var isActiveClaim = identity.SingleOrDefault(p => p.Type == "IsActive");
                if (isActiveClaim != null)
                {
                    var removeClaimResult = await _userManager.RemoveClaimAsync(user, new System.Security.Claims.Claim(isActiveClaim.Type, isActiveClaim.Value));
                    if (!removeClaimResult.Succeeded)
                    {
                        foreach (var error in removeClaimResult.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                        return View(serviceEngineer);
                    }
                }
                var addClaimResult = await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", serviceEngineer.Registration.IsActive.ToString()));
                if (!addClaimResult.Succeeded)
                {
                    foreach (var error in addClaimResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(serviceEngineer);
                }
            }
            else
            {
                // Create User
                IdentityUser user = new IdentityUser
                {
                    UserName = serviceEngineer.Registration.UserName,
                    Email = serviceEngineer.Registration.Email,
                    EmailConfirmed = true
                };
                IdentityResult result = await _userManager.CreateAsync(user, serviceEngineer.Registration.Password);
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(serviceEngineer);
                }

                // Add claims
                await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", serviceEngineer.Registration.Email));
                await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", serviceEngineer.Registration.IsActive.ToString()));

                // Assign user to Engineer Role
                var roleResult = await _userManager.AddToRoleAsync(user, Roles.Engineer.ToString());
                if (!roleResult.Succeeded)
                {
                    foreach (var error in roleResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(serviceEngineer);
                }
            }

            // Send Email
            if (serviceEngineer.Registration.IsActive)
            {
                await _emailSender.SendEmailAsync(serviceEngineer.Registration.Email, "Account Created/Modified", $"Email : {serviceEngineer.Registration.Email} \n Password : {serviceEngineer.Registration.Password}");
            }
            else
            {
                await _emailSender.SendEmailAsync(serviceEngineer.Registration.Email, "Account Deactivated", $"Your account has been deactivated.");
            }

            return RedirectToAction("ServiceEngineers");
        }
        catch (Exception ex)
        {
            ModelState.AddModelError("", $"An error occurred: {ex.Message}");
            return View(serviceEngineer);
        }
    }

  // Khách hàng
    [HttpGet]
    public async Task<IActionResult> Customers()
    {
        var customers = await _userManager.GetUsersInRoleAsync(Roles.User.ToString());
        HttpContext.Session.SetSession("Customers", customers);
        return View(new CustomerViewModel
        {
            Customers = customers?.ToList() ?? new List<IdentityUser>(),
            Registration = new CustomerRegistrationViewModel { IsEdit = false }
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Customers(CustomerViewModel customer)
    {
        if (!ModelState.IsValid)
        {
            return View(customer);
        }

        try
        {
            var user = await _userManager.FindByEmailAsync(customer.Registration.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "User not found.");
                return View(customer);
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var isActiveClaim = claims.FirstOrDefault(c => c.Type == "IsActive");

            if (isActiveClaim != null)
            {
                await _userManager.RemoveClaimAsync(user, isActiveClaim);
            }

            await _userManager.AddClaimAsync(user, new Claim("IsActive", customer.Registration.IsActive.ToString()));

            if (customer.Registration.IsActive)
            {
                await _emailSender.SendEmailAsync(user.Email, "Account Activated",
                    $"Your account has been activated. Email: {user.Email}");
            }
            else
            {
                await _emailSender.SendEmailAsync(user.Email, "Account Deactivated",
                    "Your account has been deactivated.");
            }

            // Refresh the customer list
            var customers = await _userManager.GetUsersInRoleAsync(Roles.User.ToString());
            HttpContext.Session.SetSession("Customers", customers);

            return RedirectToAction("Customers");
        }
        catch (Exception ex)
        {
            ModelState.AddModelError("", $"An error occurred: {ex.Message}");
            return View(customer);
        }
    }


}
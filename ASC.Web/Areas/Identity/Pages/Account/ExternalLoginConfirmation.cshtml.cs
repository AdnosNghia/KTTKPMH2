using ASC.Model.BaseTypes;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace ASC.Web.Areas.Identity.Pages.Account
{

    public class ExternalLoginConfirmationModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;


        public ExternalLoginConfirmationModel(SignInManager<IdentityUser> signInManager,
            ILogger<LoginModel> logger,
            UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]

        public InputModel Input { get; set; }


        public class InputModel
        {
            [Required]
            [EmailAddress]

            public string Email { get; set; }
        }


        public void OnGet()
        {
        }

        public async Task<ActionResult> OnPostAsync(string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return RedirectToPage("./ExternalLoginFailure");
                }

                var user = new IdentityUser
                {
                    UserName = Input.Email,
                    Email = Input.Email,
                    EmailConfirmed = true
                };

                var result = await _userManager.CreateAsync(user);
                await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", user.Email));
                await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "true"));
                if (!result.Succeeded)
                {
                    result.Errors.ToList().ForEach(p => ModelState.AddModelError("", p.Description));
                    return RedirectToPage("./ExternalLoginConfirmation", Input);
                }
                var roleResult = await _userManager.AddToRoleAsync(user, Roles.User.ToString());
                if (!roleResult.Succeeded)
                {
                    roleResult.Errors.ToList().ForEach(p => ModelState.AddModelError("", p.Description));
                    return RedirectToPage("./ExternalLoginConfirmation", Input);
                }
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        _logger.LogInformation(6, "User created an account using {Name} provider.", info.LoginProvider);
                        return RedirectToAction("Dashboard", "Dashboard");
                    }
                    
                }
                ModelState.AddModelError(string.Empty, result.ToString());
            }
            ViewData["ReturnUrl"] = returnUrl;
            return Page();
        }       
    }

}


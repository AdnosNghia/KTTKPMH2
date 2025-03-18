using Microsoft.AspNetCore.Identity.UI.Services;
using System.Threading.Tasks;

namespace ASC.Web.Services
{
    public class EmailSenderAdapter : Microsoft.AspNetCore.Identity.UI.Services.IEmailSender
    {
        private readonly ASC.Web.Services.IEmailSender _emailSender;

        public EmailSenderAdapter(ASC.Web.Services.IEmailSender emailSender)
        {
            _emailSender = emailSender;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            return _emailSender.SendEmailAsync(email, subject, htmlMessage);
        }
    }
}
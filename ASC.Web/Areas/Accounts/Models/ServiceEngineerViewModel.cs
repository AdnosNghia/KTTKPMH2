using Microsoft.AspNetCore.Identity;

namespace ASC.Web.Areas.Accounts.Models
{
    public class ServiceEngineerViewModel
    {
        public List<IdentityUser>? ServiceEngineers { get; set; } // Luu danh sach nhan vien
        public ServiceEngineerRegistrationViewModel Registration { get; set; } // Luu Tru nhan vien them moi hoac cap nhat
    }
}
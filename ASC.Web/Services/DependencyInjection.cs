using ASC.DataAccess.Interfaces;
using ASC.DataAccess;
using ASC.Solution.Services;
using ASC.Web.Configuration;
using ASC.Web.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ASC.Web.Data.ASC.Web.Data;

namespace ASC.Web.Services
{

    public static class DependencyInjection
    {
        // Config services
        public static IServiceCollection AddConfig(this IServiceCollection services, IConfiguration config)
        {
            // Add AddDbContext with connectionString to mirage database
            var connectionString = config.GetConnectionString("DefaultConnection") ??
                                   throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

            // Add Options and get data from appsettings.json with "AppSettings"
            services.AddOptions(); // IOption
            services.Configure<ApplicationSettings>(config.GetSection("AppSettings"));

            return services;
        }

        // Add service
        public static IServiceCollection AddMyDependencyGroup(this IServiceCollection services)
        {
            // Add IdentityUser IdentityUser
            services.AddIdentity<IdentityUser, IdentityRole>((options) =>
            {
                options.User.RequireUniqueEmail = true;
            }).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

            // Add services
            services.AddTransient<ASC.Web.Services.IEmailSender, AuthMessageSender>();
            services.AddTransient<Microsoft.AspNetCore.Identity.UI.Services.IEmailSender, EmailSenderAdapter>();
            services.AddTransient<ISmsSender, AuthMessageSender>();


            services.AddSingleton<IIdentitySeed, IdentitySeed>();
            services.AddScoped<IUnitOfWork, UnitOfWork>();

            // Thêm Cache và Session
            services.AddSession();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddDistributedMemoryCache(); // Thêm bộ nhớ cache phân tán
            services.AddSingleton<INavigationCacheOperations, NavigationCacheOperations>();

            // Add RazorPages, MVC
            services.AddRazorPages();
            services.AddDatabaseDeveloperPageExceptionFilter();

            services.AddControllersWithViews();

            services.Configure<DataProtectionTokenProviderOptions>(opt =>
    opt.TokenLifespan = TimeSpan.FromHours(2)); // Tăng thời gian lên nếu cần


            return services;
        }
    }
}
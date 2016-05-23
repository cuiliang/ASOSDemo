using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Itemz.Data;
using Itemz.Models;
using Itemz.Services;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Itemz.infrastructure.Extensions;
using Microsoft.AspNetCore.Http;
using AspNet.Security.OAuth.Validation;
using Itemz.infrastructure.Oidc;

namespace Itemz
{
    public class Startup
    {
        private IHostingEnvironment _env;

        public Startup(IHostingEnvironment env)
        {
            _env = env;


            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets();

                // This will push telemetry data through Application Insights pipeline faster, allowing you to view results immediately.
                builder.AddApplicationInsightsSettings(developerMode: true);
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
           
            


            // Add framework services.
            services.AddApplicationInsightsTelemetry(Configuration);

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddMvc();

            services.AddCors();

            // Add application services.
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();

            //setup Oidc
            OidcClientManager oidcClientMgr = new OidcClientManager();
            oidcClientMgr.AddClient(new OidcClient
            {
                ClientId = "itemzWeb",
                DisplayName = "itemz web app",
                RedirectUri = "http://localhost:4200",
                LogoutRedirectUri = "http://localhost:4200",
                Secret = "secret"
            });
            services.AddSingleton(oidcClientMgr);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            //loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddConsole(LogLevel.Trace);
            loggerFactory.AddDebug(LogLevel.Trace);

            app.UseApplicationInsightsRequestTelemetry();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseApplicationInsightsExceptionTelemetry();

            // 启用IdentityServer

            app.UseOpenIdConnectServer(options =>
            {
                //options.UseJwtTokens();
                options.Provider = new ItemzOidcProvider();
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;

                //var cert = new X509Certificate2(Path.Combine(_env.ContentRootPath, "idsrv3test.pfx"), "idsrv3test");
                //options.SigningCredentials.AddCertificate(cert);
            });


            app.UseWhen(context => context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {

                branch.UseCors(builder =>
                {
                    builder.AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod();                    
                });


                branch.UseOAuthValidation();

                //branch.UseOAuthValidation(new OAuthValidationOptions
                //{
                //    AutomaticAuthenticate = true,
                //    AutomaticChallenge = true
                //});

                //app.UseJwtBearerAuthentication(new JwtBearerOptions
                //{
                //    AutomaticAuthenticate = true,
                //    AutomaticChallenge = true,
                //    RequireHttpsMetadata = false,
                //    Audience = "http://localhost:8000/",
                //    Authority = "http://localhost:8000/"
                //});
            });

            app.UseWhen(context => !context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {               

                branch.UseIdentity();

                // Add external authentication middleware below. To configure them please see http://go.microsoft.com/fwlink/?LinkID=532715
                branch.UseGoogleAuthentication(new GoogleOptions
                {
                    ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com",
                    ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f"
                });

                //branch.UseTwitterAuthentication(new TwitterOptions
                //{
                //    ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g",
                //    ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI"
                //});
            });

           

            app.UseStaticFiles();

            

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");

                routes.MapRoute(
                    name: "api",
                    template: "api/{controller=Home}/{action=Index}/{id?}"
                    );
            });
        }

        /// <summary>
        /// 配置Identity Server
        /// </summary>
        private void ConfigIdentityServer(IApplicationBuilder app)
        {

        }
    }
}

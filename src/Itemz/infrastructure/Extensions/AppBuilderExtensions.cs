using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;

namespace Itemz.infrastructure.Extensions
{
    public static class AppBuilderExtensions
    {
        /// <summary>
        /// 条件符合时执行指定的MiddleWare
        /// </summary>
        public static IApplicationBuilder UseWhen(this IApplicationBuilder app,
            Func<HttpContext, bool> condition, Action<IApplicationBuilder> configuration)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (condition == null)
            {
                throw new ArgumentNullException(nameof(condition));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var builder = app.New();
            configuration(builder);

            return app.Use(next => {
                builder.Run(next);

                var branch = builder.Build();

                return context => {
                    if (condition(context))
                    {
                        return branch(context);
                    }

                    return next(context);
                };
            });
        }
    }
}

//MIT License

//Copyright (c) 2022 Adita

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using System.Diagnostics;
using System.Reflection;

namespace Adita.PlexNet.Core.Security.Authorization
{
    /// <summary>
    /// Represents a role based authorization manager.
    /// </summary>
    public class AuthorizationManager : IAuthorizationManager
    {
        #region Public methods
        /// <summary>
        /// Attemp to check whether the caller has permission to access the resource that the caller in.
        /// </summary>
        /// <remarks>
        /// This method checking for the <see cref="AuthorizeAttribute" /> on the caller method.
        /// </remarks>
        /// <returns>Whether the caller has permission.</returns>
        public bool CheckPermission()
        {
            Attribute? attribute = new StackFrame(1).GetMethod()?.GetCustomAttribute(typeof(AuthorizeAttribute));

            if (attribute is AuthorizeAttribute authorizeAttribute)
            {

                if (string.IsNullOrWhiteSpace(authorizeAttribute.Roles) && Thread.CurrentPrincipal?.Identity?.IsAuthenticated == true)
                {
                    return true;
                }

                foreach (var role in authorizeAttribute.Roles.Split(','))
                {
                    bool? isAuthorized = Thread.CurrentPrincipal?.IsInRole(role);

                    if (isAuthorized == true)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        /// <summary>
        /// Returns whether the caller has permission to access the specified <paramref name="resourceName" />.
        /// </summary>
        /// <typeparam name="T">The type that encapsulating the resource.</typeparam>
        /// <remarks>
        /// This method checking for the <see cref="AuthorizeAttribute" /> on the specified <paramref name="resourceName" />.
        /// </remarks>
        /// <param name="resourceName">The resource to check.</param>
        /// <returns>Whether the caller has permission.</returns>
        public bool HasPermission<T>(string resourceName)
        {
            MemberInfo[] memberInfo = typeof(T).GetMember(resourceName);

            Attribute? attribute = memberInfo[0].GetCustomAttribute(typeof(AuthorizeAttribute));

            if (attribute is AuthorizeAttribute authorizeAttribute)
            {
                if (string.IsNullOrWhiteSpace(authorizeAttribute.Roles) && Thread.CurrentPrincipal?.Identity?.IsAuthenticated == true)
                {
                    return true;
                }

                foreach (var role in authorizeAttribute.Roles.Split(','))
                {
                    bool? isAuthorized = Thread.CurrentPrincipal?.IsInRole(role);

                    if (isAuthorized == true)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        /// <summary>
        /// Returns whether current <see cref="IAuthorizationManager" /> is on specified <paramref name="role" />.
        /// </summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns><see langword="true" /> if the current <see cref="IAuthorizationManager" /> is on specified <paramref name="role" />; otherwise, <see langword="false" />.</returns>
        public bool IsInRole(string role) => Thread.CurrentPrincipal?.IsInRole(role) ?? false;
        #endregion Public methods
    }
}

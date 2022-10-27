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

namespace Adita.PlexNet.Core.Security.Authorization
{
    /// <summary>
    /// Provides an abstraction for a role based authorization manager.
    /// </summary>
    public interface IAuthorizationManager
    {
        #region Methods
        /// <summary>
        /// Attemp to check whether the caller has permission to access the resource that the caller in.
        /// </summary>
        /// <remarks>
        /// This method checking for the <see cref="AuthorizeAttribute"/> on the caller method.
        /// </remarks>
        /// <returns>Whether the caller has permission.</returns>
        bool CheckPermission();
        /// <summary>
        /// Returns whether the caller has permission to access the specified <paramref name="resourceName"/>.
        /// </summary>
        /// <typeparam name="T">The type that encapsulating the resource.</typeparam>
        /// <remarks>
        /// This method checking for the <see cref="AuthorizeAttribute"/> on the specified <paramref name="resourceName"/>.
        /// </remarks>
        /// <param name="resourceName">The resource to check.</param>
        /// <returns>Whether the caller has permission.</returns>
        bool HasPermission<T>(string resourceName);
        /// <summary>
        /// Returns whether current <see cref="IAuthorizationManager"/> is on specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns><see langword="true"/> if the current <see cref="IAuthorizationManager"/> is on specified <paramref name="role"/>; otherwise, <see langword="false"/>.</returns>
        bool IsInRole(string role);
        #endregion Methods
    }
}

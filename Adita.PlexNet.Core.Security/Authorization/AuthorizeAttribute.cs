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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Adita.PlexNet.Core.Security.Authorization
{
    /// <summary>
    /// Specifies that the field, property or method that this attribute is applied to requires the specified authorization
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Method | AttributeTargets.Field, AllowMultiple = false)]
    public class AuthorizeAttribute : Attribute
    {
        #region Constructors
        /// <summary>
        /// Initialize a new instance of <see cref="AuthorizeAttribute"/>.
        /// </summary>
        public AuthorizeAttribute() { }
        /// <summary>
        /// Initialize a new instance of <see cref="AuthorizeAttribute"/> using specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">A role name to include.</param>
        public AuthorizeAttribute(string role)
        {
            Roles = role;
        }
        #endregion Constructors

        #region Public properties
        /// <summary>
        /// Gets a comma delimited list of roles that are allowed to access the resource.
        /// </summary>
        public string Roles { get; } = string.Empty;
        #endregion Public properties
    }
}

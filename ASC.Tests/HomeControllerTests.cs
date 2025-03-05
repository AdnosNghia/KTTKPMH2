using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ASC.Tests.TestUtilities;
using ASC.Web.Configuration;
using ASC.Web.Controllers;
using ASC.Web.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using ASC.Utilities;

namespace ASC.Tests
{
    public class HomeControllerTests
    {
        private readonly Mock<IOptions<ApplicationSettings>> optionsMock;
        private readonly Mock<HttpContext> mockHttpContext;
        public HomeControllerTests()
        {
            optionsMock = new Mock<IOptions<ApplicationSettings>>();

            mockHttpContext = new Mock<HttpContext>();

            mockHttpContext.Setup(p => p.Session).Returns(new FakeSession());
            optionsMock.Setup(ap => ap.Value).Returns(new ApplicationSettings
            {
                ApplicationTitle = "ASC"
            });
        }
        [Fact]
        public void HomeController_Index_View_Test()
        {
            var mockLogger = new Mock<ILogger<HomeController>>();
            var mockEmailSender = new Mock<IEmailSender>();

            var controller = new HomeController(
                mockLogger.Object,
                optionsMock.Object,
                mockEmailSender.Object
            );

            controller.ControllerContext.HttpContext = mockHttpContext.Object; // Thêm dòng này

            Assert.IsType(typeof(ViewResult), controller.Index());
        }

        [Fact]
        public void IndexController_Index_NoModel_Test()
        {
            var mockLogger = new Mock<ILogger<HomeController>>();
            var mockEmailSender = new Mock<IEmailSender>();

            var controller = new HomeController(
                mockLogger.Object,
                optionsMock.Object,
                mockEmailSender.Object
            );

            controller.ControllerContext.HttpContext = mockHttpContext.Object;

            var result = controller.Index() as ViewResult;
            Assert.Null((controller.Index() as ViewResult).ViewData.Model);
        }

        [Fact]
        public void HomeController_Index_Validation_Test()
        {
            var mockLogger = new Mock<ILogger<HomeController>>();
            var mockEmailSender = new Mock<IEmailSender>();

            var controller = new HomeController(
                mockLogger.Object,
                optionsMock.Object,
                mockEmailSender.Object
            );

            controller.ControllerContext.HttpContext = mockHttpContext.Object;

            var result = controller.Index() as ViewResult;
            Assert.Equal(0, (controller.Index() as ViewResult).ViewData.ModelState.ErrorCount);
        }
        [Fact]
        public void HomeController_Index_Session_Test()
        {
            var mockLogger = new Mock<ILogger<HomeController>>();
            var mockEmailSender = new Mock<IEmailSender>();

            var controller = new HomeController(
                mockLogger.Object,
                optionsMock.Object,
                mockEmailSender.Object
            );
            controller.ControllerContext.HttpContext = mockHttpContext.Object;
            controller.Index();

            //Session value with key "Test" should not be null.
            Assert.NotNull(controller.HttpContext.Session.GetSession<ApplicationSettings>("Test"));
        }
    }
}
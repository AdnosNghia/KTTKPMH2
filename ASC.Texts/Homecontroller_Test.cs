using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ASC.Web.Configuration;
using Microsoft.CodeAnalysis.Options;
using Moq;
using ASC.Web.Controllers;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
namespace ASC.Texts
{
    public class Homecontroller_Test
    {
        private readonly Mock<IOptions<ApplicationSettings>> optionsMock;
        public Homecontroller_Test()
        {
            optionsMock = new Mock<IOptions<ApplicationSettings>>();

            optionsMock.Setup(option => option.Value).Returns(new ApplicationSettings
            {
                ApplicationTitle = "ASC",
            }
            );


        }

        [Fact]
        public void HomeController_Index_View_Test()
        {
            // Home controller instantiated with Mock IOptions<> object
            var controller = new HomeController(optionsMock.Object);
            //Assert return ViewResult
            Assert.IsType(typeof(ViewResult), controller.IndexTest());
        }

        [Fact]
        public void HomeController_Index_NoModel_Test()
        {
            var controller = new HomeControllerT(optionsMock.Object);
            // Assert Model for Null
            Assert.Null((controller.IndexTest() as ViewResult).ViewData.Model);
        }

        [Fact]
        public void HomeController_Index_Validation_Test()
        {
            var controller = new HomeController(optionsMock.Object);
            // Assert ModelState Error Count to 0
            Assert.Equal(0, (controller.IndexTest() as ViewResult).ViewData.ModelState.ErrorCount);
        }
    }
}

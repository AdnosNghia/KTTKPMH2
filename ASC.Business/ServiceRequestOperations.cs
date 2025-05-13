using ASC.Business.Interfaces;
using ASC.DataAccess;
using ASC.DataAccess.Interfaces;
using ASC.Model.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Business
{
    public class ServiceRequestOperations : IServiceRequestOperations
    {
        private readonly IUnitOfWork _uniOfWork;

        public ServiceRequestOperations(IUnitOfWork uniOfWork)
        {
            _uniOfWork = uniOfWork;
        }
        public async Task CreateServiceRequestAsync(ServiceRequest request)
        {
            using (_uniOfWork)
            {
                await _uniOfWork.Repository<ServiceRequest>().AddAsync(request);
                _uniOfWork.CommitTransaction();

            }
        }

        public ServiceRequest UpdateServiceRequest(ServiceRequest request)
        {
            using (_uniOfWork)
            {
                _uniOfWork.Repository<ServiceRequest>().Update(request);
                _uniOfWork.CommitTransaction();
                return request;
            }
        }

        public async Task<ServiceRequest> UpdateServiceRequestStatusAsync(string rowKey, string partitionKey, string status)
        {
            using (_uniOfWork)
            {
                var serviceRequest = await _uniOfWork.Repository<ServiceRequest>().FindAsync(partitionKey, rowKey);
                if (serviceRequest == null)
                    throw new NullReferenceException();
                serviceRequest.Status = status;
                _uniOfWork.Repository<ServiceRequest>().Update(serviceRequest);
                _uniOfWork.CommitTransaction();
                return serviceRequest;
            }
        }
    }
}
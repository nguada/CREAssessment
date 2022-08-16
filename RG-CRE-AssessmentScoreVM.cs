using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace CRE.RiskAnalysis
{
    //Author: Nestr Guadarrama
    //Date: 2022-08-09
    //Purpose: HTTP function (POST) that calculates risk scores for VM resources based on a preconfigured settings to analyze
    //         Resiliency, Performance, Security, High Availability, Management | Monitoring, Scalability and Capacity
    // Parameters:
    //      ResourceTypeId:         Resource type identification for VMs
    //      AssessmentId:           Assessment identification by customer analysis
    //      AssessmentWorkflowId:   Workflow identification related to specific risk analysis execution
    //      ServiceTypeId:          Service identification for Compute, Storage, Networking, etc.
    
    public static class RG_CRE_AssessmentScoreVM
    {
        [FunctionName("RG_CRE_AssessmentScoreVM")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req, ILogger log)
        {
            // Logging invokation
            log.LogInformation($"Function RG_CRE_AssessmentScoreVM has been invoked: {System.DateTime.UtcNow.ToString()}");

            // Defining variables to persist data
            List<AreaEvaluation> dataArea = new List<AreaEvaluation>();
            List<VMHARiskAnalysis> dataVM = new List<VMHARiskAnalysis>();
            List<ResourceType> dataResource = new List<ResourceType>();
            List<AssessmentArea> dataAssessmentArea = new List<AssessmentArea>();
            List<ServiceType> dataService = new List<ServiceType>();
            string _AssessmentId = string.Empty;
            string _WorkFlowId = string.Empty;
            string _ServiceId = string.Empty;
            decimal _TotalScore = 0.0M;

            string requestBody = String.Empty;
            using (StreamReader streamReader =  new  StreamReader(req.Body))
            {
                requestBody = await streamReader.ReadToEndAsync();
            }

            // Reading request body
            log.LogInformation($"Function RG_CRE_AssessmentScoreVM reading body");

            if (string.IsNullOrEmpty(requestBody)) 
            { 
                string errorMessage = $"Request has aborted. Bad Request. Body is empty!";
                return new BadRequestObjectResult(errorMessage);                
            }
            else            
            {
                dynamic data = JsonConvert.DeserializeObject(requestBody);
                _AssessmentId = data.AssessmentId;
                _WorkFlowId = data.AssessmentWorkflowId;
                _ServiceId = data.ServiceTypeId; 
            };


            // Retrieving connection string
            var _ConStr = System.Environment.GetEnvironmentVariable("ConnectionStrings:DBAssessmentSQL");

            // Catching any exception in SQL operaitons
            try
            {
                // Connecting to DB
                // Logging DB
                log.LogInformation($"Function RG_CRE_AssessmentScoreVM is trying to connect with DB");
                using (SqlConnection conn = new SqlConnection(_ConStr))                
                {
                    // Open connection
                    await conn.OpenAsync().ConfigureAwait(false);

                    // Retriving Areas select
                    var _tSQLAreaEvaluation = System.Environment.GetEnvironmentVariable("T-SQL-RetrieveAreaEvaluation");

                    // Logging Reader
                    log.LogInformation($"Function RG_CRE_AssessmentScoreVM is reading Areas of Evaluation");
                    // Executing query for retrieving areas of evaluation
                    using(SqlCommand comm = new SqlCommand(_tSQLAreaEvaluation, conn))
                    {
                        
                        using (SqlDataReader reader = comm.ExecuteReader())
                        {
                            // Reading
                            while(reader.Read())
                            {
                                dataArea.Add(new AreaEvaluation() {
                                    ResourceAreaEvaluationId = reader.GetValue(0).ToString(),
                                    ResourceTypeId = reader.GetValue(1).ToString(),
                                    AssessmentAreaId = reader.GetValue(2).ToString(),
                                    ResourceAreaEvaluationName = reader.GetValue(3).ToString(),
                                    ResourceAreaEvaluationPriority = Convert.ToInt16((reader.GetValue(4)))
                                });
                            }
                        }
                    }

                    // Retrieve resource types
                    var _tSQLResources = System.Environment.GetEnvironmentVariable("T-SQL-RetrieveResourceType");

                    // Logging Reader
                    log.LogInformation($"Function RG_CRE_EvaluationScoreVM is reading Resource Types");
                    // Executing query for retrieving areas of evaluation
                    using(SqlCommand comm = new SqlCommand(_tSQLResources, conn))
                    {
                        
                        using (SqlDataReader reader = comm.ExecuteReader())
                        {
                            // Reading
                            while(reader.Read())
                            {
                                dataResource.Add(new ResourceType() {
                                ResourceTypeId = reader.GetValue(0).ToString(),
                                ServiceTypeId = reader.GetValue(1).ToString(),
                                ResourceTypeName = reader.GetValue(2).ToString()
                                });
                            }
                        }
                    }

                    // Retrieve areas
                    var _tSQLArea = System.Environment.GetEnvironmentVariable("T-SQL-RetrieveAssessmentArea");

                    // Logging Reader
                    log.LogInformation($"Function RG_CRE_EvaluationScoreVM is reading Area");
                    // Executing query for retrieving areas of evaluation
                    using(SqlCommand comm = new SqlCommand(_tSQLArea, conn))
                    {
                        
                        using (SqlDataReader reader = comm.ExecuteReader())
                        {
                            // Reading
                            while(reader.Read())
                            {
                                dataAssessmentArea.Add(new AssessmentArea {
                                AssessmentAreaId = reader.GetValue(0).ToString(),
                                AssessmentAreaName = reader.GetValue(1).ToString(),
                                AssessmentAreaDescription = reader.GetValue(2).ToString(),
                                AssessmentAreaRepresentation = reader.GetValue(3).ToString()
                                });
                            }
                        }
                    }        

                    // Retrieve services
                    var _tSQLService = System.Environment.GetEnvironmentVariable("T-SQL-RetrieveServiceType");

                    // Logging Reader
                    log.LogInformation($"Function RG_CRE_EvaluationScoreVM is reading Services");
                    // Executing query for retrieving areas of evaluation
                    using(SqlCommand comm = new SqlCommand(_tSQLService, conn))
                    {
                        
                        using (SqlDataReader reader = comm.ExecuteReader())
                        {
                            // Reading
                            while(reader.Read())
                            {
                                dataService.Add(new ServiceType {
                                ServiceTypeId = reader.GetValue(0).ToString(),
                                ServiceTypeName = reader.GetValue(1).ToString()
                                });
                            }
                        }
                    }        

                    // Retrieve VMs select
                    var _tSQLVMs = System.Environment.GetEnvironmentVariable("T-SQL-RetrieveVMHARiskAnalysis").ToString().Replace("{P1}", _AssessmentId).Replace("{P2}", _WorkFlowId).Replace("{P3}", _ServiceId);

                    // Logging Reader
                    log.LogInformation($"Function RG_CRE_AssessmentScoreVM is reading VMs");

                    // Executing query for retrieving VMs
                    using(SqlCommand comm = new SqlCommand(_tSQLVMs, conn))
                    {
                        // Reading
                        using (SqlDataReader reader = comm.ExecuteReader())
                        {
                            while(reader.Read())
                            {
                                dataVM.Add(new VMHARiskAnalysis() {
                                    AssessmentId = reader.GetValue(0).ToString(),
                                    AssessmentWorkflowId = reader.GetValue(1).ToString(),
                                    ServiceTypeId = reader.GetValue(2).ToString(),
                                    SubscriptionId = reader.GetValue(3).ToString(),
                                    RoleInstanceName = reader.GetValue(4).ToString(),
                                    SingleInstance = Convert.ToBoolean(reader.GetValue(5)),
                                    AvailabilitySet = Convert.ToBoolean(reader.GetValue(6)),
                                    VMSSSetup = Convert.ToBoolean(reader.GetValue(7)),
                                    AvailabilityZoneSetup = Convert.ToBoolean(reader.GetValue(8)),
                                    SMD_HDD = Convert.ToBoolean(reader.GetValue(9)),
                                    SMD_SDD = Convert.ToBoolean(reader.GetValue(10)),
                                    PMD_SDD = Convert.ToBoolean(reader.GetValue(11)),
                                    ULT_SDD = Convert.ToBoolean(reader.GetValue(12)),
                                    STD_StorageAccount = Convert.ToBoolean(reader.GetValue(13)),
                                    PRM_StorageAccount = Convert.ToBoolean(reader.GetValue(14)),
                                    MAB = Convert.ToBoolean(reader.GetValue(15)),
                                    DHG_Group = Convert.ToBoolean(reader.GetValue(16)),
                                });
                            }
                        }
                    }
                }
            }
            catch (System.Exception e)
            {
                log.LogError(e, e.Message.ToString());
                string errorMessage = $"Request has aborted. Bad Request. Exception message: {e.Message.ToString()}";
                return new BadRequestObjectResult(errorMessage);
                //throw;
            }

            // Catching any exception in SQL operaitons
            try
            {
                // Logging Reader
                log.LogInformation($"Function RG_CRE_AssessmentScoreVM is calculating scores for each VM");

                // Invoke SP to update scores
                using (SqlConnection conn = new SqlConnection(_ConStr))                
                {
                    // Open connection
                    await conn.OpenAsync().ConfigureAwait(false);
                    // Logging SP

                    // Creating Command object
                    SqlCommand _comm = new SqlCommand(System.Environment.GetEnvironmentVariable("T-SQL-SP_Update_Score_VMs_HA"), conn);
                    _comm.CommandType = System.Data.CommandType.StoredProcedure;

                    // Calculating max number of evaluation areas for score percentage
                    // ADDING A FOOD VALUE AS ADDITIONAL CALCULATIONS MUST BE COMPLETED
                    //var _maxScore = dataArea.Sum(s => s.ResourceAreaEvaluationPriority);
                    var _maxScore = 24;

                    // Calculate Score
                    decimal v_Score = 0;
                    foreach (VMHARiskAnalysis VM in dataVM)
                    {
                        // Validating if VM is a single instance
                        if (VM.SingleInstance == false)
                        {
                            var _value =  dataArea.Where(s => s.ResourceAreaEvaluationName == "Single Instance").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score +=  _value;
                        } 

                        // Validating if VM is part of an AS
                        if (VM.AvailabilitySet)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Availability Set").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is part of a VMSS
                        if (VM.VMSSSetup)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Virtual Machine Scale Set").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is deployed in AZ configuration
                        if (VM.AvailabilityZoneSetup)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Availability Zones").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }
                        
                        // Validating if VM is using standard HDD disk
                        if (VM.SMD_HDD)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Standard Managed Disk (HDD)").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is using standard SDD disk
                        if (VM.SMD_SDD)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Standard Managed Disk (SDD)").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is using premium SDD disk
                        if (VM.PMD_SDD)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Premium Managed Disk (SDD)").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is using ultra SDD disk
                        if (VM.ULT_SDD)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Ultra Disk (SD)").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is using standard storage account
                        if (VM.STD_StorageAccount)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Standard Storage Account").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM is using premium storage account
                        if (VM.PRM_StorageAccount)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Premium Storage Account").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM has set backups
                        if (VM.MAB)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Azure Backup").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        }

                        // Validating if VM has set Dedicated host Group
                        if (VM.DHG_Group)
                        {
                            var _value = dataArea.Where(s => s.ResourceAreaEvaluationName == "Dedicated Host Group").Select(s => s.ResourceAreaEvaluationPriority).FirstOrDefault();
                            v_Score += _value;
                        } 

                        ///
                        ///PLACEHODER FOR CALCULATING SLA BASED ON STORAGE ACCOUNT AND DISK CONFIGURATION
                        ///

                        // Asigning score to scoreRaw in item
                        VM.Score_Raw = Convert.ToDecimal(v_Score);

                        // Calculate score percentage taking max number of attributes in Area Evaluation
                        decimal _scorePercentage = 1 -(v_Score/Convert.ToDecimal(_maxScore));
                        _TotalScore += _scorePercentage;

                        // Invoking SP
                        _comm.Parameters.Add("AssessmentId", System.Data.SqlDbType.UniqueIdentifier).Value =  new Guid(VM.AssessmentId);
                        _comm.Parameters.Add("AssessmentWorkflowId", System.Data.SqlDbType.UniqueIdentifier).Value = new Guid(VM.AssessmentWorkflowId);                        
                        _comm.Parameters.Add("ServiceTypeId", System.Data.SqlDbType.UniqueIdentifier).Value = new Guid(VM.ServiceTypeId);
                        _comm.Parameters.Add("SubscriptionId", System.Data.SqlDbType.UniqueIdentifier).Value = new Guid(VM.SubscriptionId);
                        _comm.Parameters.Add("RoleInstanceName", System.Data.SqlDbType.NVarChar).Value = VM.RoleInstanceName.ToString();
                        _comm.Parameters.Add("Score", System.Data.SqlDbType.Decimal).Value = v_Score;
                        _comm.Parameters.Add("ScorePercentage", System.Data.SqlDbType.Decimal).Value = _scorePercentage;

                        await _comm.ExecuteNonQueryAsync().ConfigureAwait(false);

                        // Cleaning Parameters
                        _comm.Parameters.Clear();

                        // Cleaning variables
                        v_Score = 0;
                        _scorePercentage = 0;
                    }
                
                    // Calculating score average for VMs HA
                    _TotalScore = _TotalScore / dataVM.Count();

                    _comm = new SqlCommand(System.Environment.GetEnvironmentVariable("T-SQL-SP_Insert_AssessementScore"), conn);
                    _comm.CommandType = System.Data.CommandType.StoredProcedure;
                    _comm.Parameters.Add("AssessmentId", System.Data.SqlDbType.UniqueIdentifier).Value =  new Guid(_AssessmentId);
                    _comm.Parameters.Add("AssessmentAreaId", System.Data.SqlDbType.UniqueIdentifier).Value = new Guid(dataAssessmentArea.Where(s => s.AssessmentAreaRepresentation == "HA").Select(s => s.AssessmentAreaId).FirstOrDefault());
                    _comm.Parameters.Add("ServiceTypeId", System.Data.SqlDbType.UniqueIdentifier).Value = new Guid(dataService.Where(s => s.ServiceTypeName == "Compute").Select(s => s.ServiceTypeId).FirstOrDefault());
                    _comm.Parameters.Add("ResourceTypeId", System.Data.SqlDbType.UniqueIdentifier).Value = new Guid(dataResource.Where(s => s.ResourceTypeName == "Virtual Machine").Select(s => s.ResourceTypeId).FirstOrDefault());
                    _comm.Parameters.Add("Assessment_Score", System.Data.SqlDbType.Decimal).Value = _TotalScore;

                    await _comm.ExecuteNonQueryAsync().ConfigureAwait(false);

                    // Cleaning Parameters
                    _comm.Parameters.Clear();

                    // Cleaning variables
                    _TotalScore = 0;
                }
            }
            catch (System.Exception e)
            {
                log.LogError(e, e.Message.ToString());
                string errorMessage = $"Request has aborted. Bad Request. Exception message: {e.Message.ToString()}";
                return new BadRequestObjectResult(errorMessage);
                //throw;
            }

            // Logging Reader
            log.LogInformation($"Function RG_CRE_AssessmentScoreVM is returning OK. No error found.");

            // Returning number of updated resources 
            return new OkObjectResult($"Function RG_CRE_AssessmentScoreVM is returning OK. Number of updated records: {dataVM.Count}.");
        }
    }

    public class AreaEvaluation
    {
        public string ResourceAreaEvaluationId {get; set;}
        public string ResourceTypeId {get; set;}
        public string AssessmentAreaId {get; set;}
        public string ResourceAreaEvaluationName {get; set;}
        public Int16 ResourceAreaEvaluationPriority {get; set;}
    }

    public class VMHARiskAnalysis
    {
        public string AssessmentId {get; set;}
        public string AssessmentWorkflowId {get; set;}
         public string ServiceTypeId {get; set;}
         public string SubscriptionId {get; set;}
         public string RoleInstanceName {get; set;}
         public bool SingleInstance {get; set;}
         public bool AvailabilitySet {get; set;}
         public bool VMSSSetup {get; set;}
         public bool AvailabilityZoneSetup {get; set;}
         public bool SMD_HDD {get;set;}
         public bool SMD_SDD {get;set;}
         public bool PMD_SDD {get;set;}
         public bool ULT_SDD {get;set;}
         public bool STD_StorageAccount {get; set;}
         public bool PRM_StorageAccount {get; set;}
         public bool MAB {get; set;}
         public bool DHG_Group {get; set;}
         public decimal Score_Raw {get; set;}
    }

    public class ResourceType
    {
        public string ResourceTypeId { get; set; }
        public string ServiceTypeId { get; set; }
        public string ResourceTypeName { get; set; }
    }

    public class AssessmentArea{
        public string AssessmentAreaId { get; set; }
        public string AssessmentAreaName { get; set; }
        public string AssessmentAreaDescription { get; set; }
        public string AssessmentAreaRepresentation { get; set; }
    }

    public class ServiceType{
        public string ServiceTypeId { get; set; }

        public string ServiceTypeName { get; set; }
    }
}

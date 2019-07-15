#r "Newtonsoft.Json"
#r "Microsoft.WindowsAzure.Storage"

using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

public static async Task<IActionResult> Run(HttpRequest req, ILogger log)
{
  log.LogInformation("C# HTTP trigger function processed a request.");

  dynamic requestBody = await new StreamReader(req.Body).ReadToEndAsync();
  dynamic data = JsonConvert.DeserializeObject(requestBody);
  if (data.container == null)
  {
    return new BadRequestObjectResult("Specify value for 'container'");
  }

  if (data.connection == null)
  {
    return new BadRequestObjectResult("Specify value for 'connection'");
  }

  var permissions = SharedAccessBlobPermissions.Read; // default to read permissions
  if (data.permissions != null)
  {
    bool success = Enum.TryParse(data.permissions.ToString(), out permissions);
    if (!success)
    {
      return new BadRequestObjectResult("Invalid value for 'permissions'");
    }
  }
  var startTime = DateTime.UtcNow.AddMinutes(-5);
  if (data.startTime != null)
  {
    bool success = DateTime.TryParse(data.startTime.ToString(), out startTime);
    if (!success)
    {
      return new BadRequestObjectResult("Invalid value for 'startTime'");
    }
  }
  var storageAccount = CloudStorageAccount.Parse(data.connection.ToString());
  var blobClient = storageAccount.CreateCloudBlobClient();
  var container = blobClient.GetContainerReference(data.container.ToString());
  if (data.blobName == null)
  {
    return new OkObjectResult(GetContainerSasToken(container, permissions, startTime));
  }
  else
  {
    return new OkObjectResult(GetBlobSasToken(container, data.blobName.ToString(), permissions, startTime));
  }
}

public static string GetBlobSasToken(CloudBlobContainer container, string blobName, SharedAccessBlobPermissions permissions, DateTime startTime, string policyName = null)
{
  string sasBlobToken;

  // Get a reference to a blob within the container.
  // Note that the blob may not exist yet, but a SAS can still be created for it.
  CloudBlockBlob blob = container.GetBlockBlobReference(blobName);

  if (policyName == null)
  {
    var adHocSas = CreateAdHocSasPolicy(permissions, startTime);

    // Generate the shared access signature on the blob, setting the constraints directly on the signature.
    sasBlobToken = blob.GetSharedAccessSignature(adHocSas);
  }
  else
  {
    // Generate the shared access signature on the blob. In this case, all of the constraints for the
    // shared access signature are specified on the container's stored access policy.
    sasBlobToken = blob.GetSharedAccessSignature(null, policyName);
  }

  return sasBlobToken;
}

public static string GetContainerSasToken(CloudBlobContainer container, SharedAccessBlobPermissions permissions, DateTime startTime, string storedPolicyName = null)
{
  string sasContainerToken;

  // If no stored policy is specified, create a new access policy and define its constraints.
  if (storedPolicyName == null)
  {
    var adHocSas = CreateAdHocSasPolicy(permissions, startTime);

    // Generate the shared access signature on the container, setting the constraints directly on the signature.
    sasContainerToken = container.GetSharedAccessSignature(adHocSas, null);
  }
  else
  {
    // Generate the shared access signature on the container. In this case, all of the constraints for the
    // shared access signature are specified on the stored access policy, which is provided by name.
    // It is also possible to specify some constraints on an ad-hoc SAS and others on the stored access policy.
    // However, a constraint must be specified on one or the other; it cannot be specified on both.
    sasContainerToken = container.GetSharedAccessSignature(null, storedPolicyName);
  }

  return sasContainerToken;
}

private static SharedAccessBlobPolicy CreateAdHocSasPolicy(SharedAccessBlobPermissions permissions, DateTime startTime)
{
  // Create a new access policy and define its constraints.
  // Note that the SharedAccessBlobPolicy class is used both to define the parameters of an ad-hoc SAS, and 
  // to construct a shared access policy that is saved to the container's shared access policies. 

  return new SharedAccessBlobPolicy()
  {
    // Set start time to five minutes before now to avoid clock skew.
    SharedAccessStartTime = startTime,
    SharedAccessExpiryTime = DateTime.UtcNow.AddHours(1),
    Permissions = permissions
  };
}
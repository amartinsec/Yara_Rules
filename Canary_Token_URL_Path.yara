rule canarytokenpath
{
  meta:
    description = "Yara rule to detect the default canary token endpoint configuration. Will work on self hosted platforms if defaults are used. Will not detect DNS tokens."
    author = "amartin@amartinsec.com / @amartinsec"

  strings:
    $pathRegex= /\/(about|feedback|static|terms|articles|images|tags|traffic)\//
    $endpointRegex = /\/(index.html|contact.php|post.jsp|submit.aspx)/
    $trackingString = /[a-z0-9]{25}/

  condition:
    $pathRegex and $endpointRegex and $trackingString
}

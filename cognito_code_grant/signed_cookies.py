from django.conf import settings

from datetime import datetime
import time
import boto3
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from botocore.signers import CloudFrontSigner

# Heavily inspired on a couple of existing solutions in stackoverflow and AWS documentation.
# Adapted for good measure, to serve our needs.

def rsa_signer(message):
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())


def generate_signed_cookies(resource=None,expire_minutes=5):
    """
    @resource   path to s3 object inside bucket(or a wildcard path,e.g. '/blah/*' or  '*')
    @expire_minutes     how many minutes before we expire these access credentials (within cookie)
    return tuple of domain used in resource URL & dict of name=>value cookies
    """
    if not resource:
        resource = '*'

    return dist.create_signed_cookies(resource,expire_minutes=expire_minutes)


class SignedCookiedCloudfrontDistribution():

    def __init__(self,connection,download_dist_id,cname=True):
        """
        @download_dist_id   id of your Cloudfront download distribution
        @cname          boolean True to use first domain cname, False to use 
                        cloudfront domain name, defaults to cname
                        which presumably matches your writeable cookies ( .mydomain.com)
        """
        self.download_dist = None
        self.domain = None
        try:
            download_dist = connection.get_distribution(Id=download_dist_id)
            if cname and download_dist.get('Distribution', {}).get('AliasICPRecordals', {}):
                self.domain = download_dist['Distribution']['AliasICPRecordals'][0]['CNAME'] #use first cname if defined
            else:
                self.domain = download_dist.domain_name
            self.download_dist = download_dist
        except Exception as ex:
            logging.error(ex)

    def get_http_resource_url(self,resource=None,secure=False):
        """
        @resource   optional path and/or filename to the resource 
                   (e.g. /mydir/somefile.txt);
                    defaults to wildcard if unset '*'
        @secure     whether to use https or http protocol for Cloudfront URL - update  
                    to match your distribution settings 
        return constructed URL
        """
        if not resource:
            resource = '*'
        protocol = "http" if not secure else "https"
        http_resource = '%s://%s/%s' % (protocol,self.domain,resource)
        return http_resource

    def create_signed_cookies(self,resource,expire_minutes=3):
        """
        generate the Cloudfront download distirbution signed cookies
        @resource   path to the file, path, or wildcard pattern to generate policy for
        @expire_minutes  number of minutes until expiration
        return      tuple with domain used within policy (so it matches 
                    cookie domain), and dict of cloudfront cookies you
                    should set in request header
        """
        http_resource = self.get_http_resource_url(resource,secure=True)    #per-file access #NOTE secure should match security settings of cloudfront distribution

        cloudfront_signer = CloudFrontSigner(settings.SIGNED_COOKIES_CF_KEY_PAIR_ID, rsa_signer)
        expires = SignedCookiedCloudfrontDistribution.get_expires(expire_minutes)
        policy = cloudfront_signer.build_policy(http_resource,datetime.fromtimestamp(expires))
        encoded_policy = cloudfront_signer._url_b64encode(policy.encode('utf-8')).decode('utf-8')

        #assemble the 3 Cloudfront cookies
        signature = rsa_signer(policy.encode('utf-8'))
        encoded_signature = cloudfront_signer._url_b64encode(signature).decode('utf-8')
        cookies = {
            "CloudFront-Policy": encoded_policy,
            "CloudFront-Signature": encoded_signature,
            "CloudFront-Key-Pair-Id": settings.SIGNED_COOKIES_CF_KEY_PAIR_ID,
        }
        return cookies

    @staticmethod
    def get_expires(minutes):
        unixTime = time.time() + (minutes * 60)
        expires = int(unixTime)  #if not converted to int causes Malformed Policy error and has 2 decimals in value
        return expires


conn = boto3.client('cloudfront')
if getattr(settings, 'SIGNED_COOKIES', False):
    dist_id = settings.SIGNED_COOKIES_CF_DISTRIBUTION_ID
    dist = SignedCookiedCloudfrontDistribution(conn,dist_id)
    private_key = serialization.load_pem_private_key(
        settings.SIGNED_COOKIES_PRIVATE_KEY.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


def add_signed_cookies(response):
    # Generate signed cookies and add them to the response.
    # The idea is to generate the cookies at each request and have them relatively short lived.
    try:
        if getattr(settings, 'SIGNED_COOKIES', False):
            cookies = generate_signed_cookies(settings.SIGNED_COOKIES_RESOURCE)
            for key, value in cookies.items():
                response.set_cookie(key, value, domain=settings.SIGNED_COOKIES_DOMAIN)
    except Exception as ex:
        logging.error(ex)


class SignedCookiesMiddleware(object):
    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        add_signed_cookies(response)
        return response


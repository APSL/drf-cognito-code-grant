def get_cookie_domain(request):
    if 'HTTP_HOST' in request.META:
        host = request.META['HTTP_HOST']
        if 'stitch.fashion' in host:
            cookie_domain = '.stitch.fashion'
        else:
            cookie_domain = '.stitchdesignlab.com'
        return cookie_domain
    else:
        return '.stitchdesignlab.com'

def get_assets_v2_domain(request):
    return 'assets-v2' + get_cookie_domain(request)

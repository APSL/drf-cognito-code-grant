def get_cookie_domain(request):
    if 'HTTP_HOST' in request.META:
        host = request.META['HTTP_HOST']
        return host


def get_assets_v2_domain(request):
    return 'assets-v2' + get_cookie_domain(request)

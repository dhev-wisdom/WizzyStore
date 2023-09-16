from django.shortcuts import render
from .models import Product
from math import ceil

# Create your views here.
def home(request):
    current_user = request.user
    allProducts = []
    categoryProducts = Product.objects.values('category', 'id')
    categories = {item['category'] for item in categoryProducts}

    for cat in categories:
        product = Product.objects.filter(category=cat)
        n = len(product)
        nSlides = n // 4 + ceil((n / 4) - (n // 4))
        allProducts.append([product, range(1, nSlides), nSlides])

    context = {'allProducts': allProducts}
    return render(request, 'home.html', context)
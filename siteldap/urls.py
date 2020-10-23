from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('home/<str:username>', views.home, name='home'),
    path('logout/<str:group>', views.my_logout, name='logout')
]

from django.urls import path

from encryoapp import views

urlpatterns = [
    path('',views.index,name='index'),
    # path('login',views.login,name='login'),
    path('loginpg',views.loginpg,name='loginpg'),
    path('logout/', views.logout_view, name='logout'),

    path('register',views.register,name='register'),
    path('userhome',views.userhome,name="userhome"),

    path('encrypt',views.encrypt,name='encrypt'), 
    path('feedback',views.feedback,name='feedback'),
    path('viewfeedback',views.viewfeedback,name='viewfeedback'),

    #   RSA ENCRYPTION PATH
    
    path('rsahome',views.rsahome,name='rsahome'),
    path('rsaencrypt',views.rsaencrypt,name='rsaencrypt'),
    path('rsadecrypt',views.rsadecrypt,name='rsadecrypt'),
    path('rsakey',views.rsakey,name="rsakey"),
    path('generate_keys',views.rsa_key_generator,name='generate_keys'),

    #   AES ENCRYPTION PATH

    path('aeshome',views.aeshome,name='aeshome'),
    path('aesencrypt', views.aesencrypt, name='aesencrypt'),
    path('aesdecrypt', views.aesdecrypt, name='aesdecrypt'),

    # ADMIN PATH

    path('adminhome',views.adminhome,name="adminhome"),
    
    path('extra',views.extra,name='extra'),
]
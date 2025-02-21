from django.contrib import admin
from .models import Country, State, City

@admin.register(Country)
class CountryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    list_filter = ['name']  
    search_fields = ['name'] 

@admin.register(City)
class CityAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    list_filter = ['name']  
    search_fields = ['name'] 

# This file is a part of OwnCA,
# Certificate Authority GUI based on Django and OpenSSL 
#
# Copyright (C) 2026 Ilya Maltsev
# email: i.y.maltsev@yandex.ru
#
# OwnCA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OwnCA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OwnCA.  If not, see <http://www.gnu.org/licenses/>.

from django.urls import path

from . import views
from .webhelp import views as webhelp_views


urlpatterns = [
    # Webhelp portal
    path('webhelp/', webhelp_views.webhelp_redirect_view, name='webhelp_redirect'),
    path('webhelp/<str:lang>/', webhelp_views.webhelp_index_view, name='webhelp_index'),
    path('webhelp/<str:lang>/search-index.json', webhelp_views.webhelp_search_index_view, name='webhelp_search_index'),
    path('webhelp/<str:lang>/<slug:slug>/', webhelp_views.webhelp_page_view, name='webhelp_page'),

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('', views.dashboard_view, name='dashboard'),

    # Certificate Authorities
    path('cas/', views.cas_view, name='cas'),
    path('cas/create/', views.ca_create_view, name='ca_create'),
    path('cas/<uuid:ca_uuid>/', views.ca_detail_view, name='ca_detail'),
    path('cas/<uuid:ca_uuid>/delete/', views.ca_delete_view, name='ca_delete'),
    path('cas/<uuid:ca_uuid>/download/', views.ca_download_cert_view, name='ca_download_cert'),
    path('cas/<uuid:ca_uuid>/crl/generate/', views.ca_generate_crl_view, name='ca_generate_crl'),
    path('cas/<uuid:ca_uuid>/crl/download/', views.ca_download_crl_view, name='ca_download_crl'),

    # Certificates
    path('certificates/', views.certificates_view, name='certificates'),
    path('certificates/csr-parse/', views.csr_parse_view, name='csr_parse'),
    path('certificates/<uuid:cert_uuid>/', views.cert_detail_view, name='cert_detail'),
    path('certificates/<uuid:cert_uuid>/download/<str:kind>/', views.cert_download_view, name='cert_download'),
    path('certificates/<uuid:cert_uuid>/revoke/', views.cert_revoke_view, name='cert_revoke'),
    path('certificates/<uuid:cert_uuid>/renew/', views.cert_renew_view, name='cert_renew'),
    path('certificates/<uuid:cert_uuid>/delete/', views.cert_delete_view, name='cert_delete'),

    # Custom certificate issuance (free-form / profile-driven)
    path('custom-cert-issue/', views.custom_cert_issue_view, name='custom_cert_issue'),

    # Certificate Profiles (extension templates)
    path('cert-profiles/', views.cert_profiles_view, name='cert_profiles'),
    path('cert-profiles/<int:cp_id>/', views.cert_profile_detail_view, name='cert_profile_detail'),
    path('cert-profiles/<int:cp_id>/delete/', views.cert_profile_delete_view, name='cert_profile_delete'),
    path('cert-profiles/<int:cp_id>/copy/', views.cert_profile_copy_view, name='cert_profile_copy'),

    # System
    path('system/configuration/', views.configuration_view, name='configuration'),
    path('system/maintenance/', views.maintenance_view, name='maintenance'),
    path('api/maintenance/refresh/', views.maintenance_refresh_api, name='maintenance_refresh'),
    path('api/maintenance/rebuild-crls/', views.maintenance_rebuild_crls_api, name='maintenance_rebuild_crls'),
    path('api/ca/<uuid:ca_uuid>/cert-profiles/', views.ca_cert_profiles_api, name='ca_cert_profiles'),
    path('api/ca/<uuid:ca_uuid>/cert-profiles/all/', views.ca_all_cert_profiles_api, name='ca_all_cert_profiles'),
]

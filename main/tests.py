# ========== Input Validation ===========
# Kirishni tekshirish

# 1. Conduct all input validation on a trusted system (server side, not client side).
# Ishonchli tizimda (mijoz tomonida emas, server tomonida) barcha kirish tekshiruvlarini o'tkazing.
# Server tomonida tekshirish

# from rest_framework import serializers
#
#
# class ProductSerializer(serializers.Serializer):
#     name = serializers.CharField(max_length=100)
#     price = serializers.DecimalField(max_digits=10, decimal_places=2)
#
#     def validate_price(self, value):
#         if value <= 0:
#             raise serializers.ValidationError("Price must be a positive number.")
#         return value



# 2. Identify all data sources and classify them into trusted and untrusted.
# Barcha ma'lumotlar manbalarini aniqlang va ularni ishonchli va ishonchsizlarga ajrating.
# Ma'lumotlar manbalarini aniqlash
# Maʼlumotlarni ishonchli (masalan, autentifikatsiya qilingan
# foydalanuvchi kiritishi) yoki ishonchsiz
# (masalan, uchinchi tomon API maʼlumotlari) deb tasniflang.


# 3. Validate all data from untrusted sources (databases, file streams, etc.).
# Ishonchsiz manbalardan (ma'lumotlar bazalari, fayl oqimlari va boshqalar) barcha ma'lumotlarni tasdiqlang.
# from rest_framework import serializers
# from rest_framework.exceptions import ValidationError
# from .models import UserProfile

from django.core.exceptions import ValidationError
#
# class UserInputSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#
#     def validate_email(self, value):
#         if not value.endswith("@unired.com"):
#             raise serializers.ValidationError("Only @example.com emails are allowed.")
#         return value


# 4. Use a centralized input validation routine for the whole application.
# Butun ilova uchun markazlashtirilgan kiritishni tekshirish tartibidan foydalaning.
# Tarqalgan tekshirish mantig'idan saqlaning. Umumiy usullar yoki yordamchi dasturlar to'plamidan foydalaning.
# class BaseValidator:
#     @staticmethod
#     def validate_phone_number(phone_number):
#         if len(phone_number) != 10 or not phone_number.isdigit():
#             raise serializers.ValidationError("Invalid phone number format.")
#
# class MySerializer(serializers.Serializer):
#     phone_number = serializers.CharField()
#
#     def validate_phone_number(self, value):
#         BaseValidator.validate_phone_number(value)
#         return value

# 5. Specify character sets, such as UTF-8, for all input sources (canonicalization).
# 5. Barcha kirish manbalari uchun UTF-8 kabi belgilar to'plamini belgilang (kanoniklashtirish).
# Belgilar to‘plami spetsifikatsiyasi
# Misol : Sozlamalaringizda UTF-8 ni belgilang:
#
# REST_FRAMEWORK = {
#     'DEFAULT_CHARSET': 'utf-8',
# }
# 6. Encode input to a common character set before validating.
# 6. Tasdiqlashdan oldin umumiy belgilar to'plamiga kirishni kodlang.
# Keyingi ishlov berishdan oldin barcha kiritilgan ma'lumotlar UTF-8 ga aylantirilganligiga ishonch hosil qiling.
#
# class MySerializer(serializers.Serializer):
#     input_text = serializers.CharField()
#
#     def validate_input_text(self, value):
#         try:
#             value = value.encode('utf-8').decode('utf-8')
#         except UnicodeDecodeError:
#             raise serializers.ValidationError("Invalid UTF-8 encoding.")
#         return value

# 7. All validation failures should result in input rejection.
# 7. Tekshirishning barcha xatolari kiritishni rad etishga olib kelishi kerak.
# Izoh : Tekshirish tekshiruvlari muvaffaqiyatsiz bo'lganda har doim xatolarni ko'taring.
# class ProductSerializer(serializers.Serializer):
#     price = serializers.DecimalField(max_digits=10, decimal_places=2)
#
#     def validate_price(self, value):
#         if value <= 0:
#             raise serializers.ValidationError("Price must be greater than zero.")
#         return value


# 8. If the system supports UTF-8 extended character sets, validate after UTF-8 decoding is completed.
# 8. Agar tizim kengaytirilgan UTF-8 belgilar to'plamini qo'llab-quvvatlasa, UTF-8 dekodlash tugagandan so'ng tasdiqlang.
# Izoh : dekodlashdan keyin tizimingiz ma'lumotlarni qayta ishlashiga ishonch hosil qiling.

# class UTF8Serializer(serializers.Serializer):
#     input_data = serializers.CharField()
#
#     def validate_input_data(self, value):
#         value = value.encode('utf-8').decode('utf-8')
#         # Perform additional validation
#         return value


# 9. Validate all client-provided data before processing.
# 9. Ishlov berishdan oldin mijoz tomonidan taqdim etilgan barcha ma'lumotlarni tasdiqlang.
# Izoh : Foydalanishdan oldin tekshirish sathi orqali barcha ma'lumotlarni ishga tushiring.

# class MyView(APIView):
#     def post(self, request):
#         serializer = MySerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         # Safe to use serializer.validated_data


# 10. Verify that protocol header values in both requests and responses contain only ASCII characters.
# 10. So'rovlar va javoblardagi protokol sarlavhasi qiymatlari faqat ASCII belgilaridan iborat ekanligini tekshiring.
# Izoh : Sarlavhalar faqat ASCII belgilarni o'z ichiga olishi uchun tozalanishi kerak.

# from rest_framework.response import Response
#
# class HeaderValidationView(APIView):
#     def get(self, request):
#         if not request.headers.get('User-Agent', '').isascii():
#             return Response({"error": "Invalid header characters."}, status=400)
#         return Response({"message": "Headers are valid."})


# 11. Validate data from redirects.
# 11. Qayta yo'naltirishdan olingan ma'lumotlarni tekshirish.
#
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# import requests
#
#
# class RedirectExampleView(APIView):
#     def get(self, request):
#         # Qayta yo'naltirilgan URL
#         redirect_url = 'https://example.com/api/redirected_data/'
#
#         # Qayta yo'naltirilgan URL dan ma'lumot olish
#         response = requests.get(redirect_url)
#
#         # Agar ma'lumotlar muvaffaqiyatli qaytgan bo'lsa, ularni tekshiramiz
#         if response.status_code == 200:
#             # Qaytgan ma'lumotlar JSON formatida bo'lishi kerak
#             data = response.json()
#
#             # Ma'lumotlar tasdiqlanganligini tekshiramiz (masalan, 'key' borligini)
#             if 'key' in data:
#                 return Response(data, status=status.HTTP_200_OK)
#             else:
#                 return Response({'error': 'Ma\'lumotlar noto\'g\'ri'}, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             return Response({'error': 'Qayta yo\'naltirishda xato yuz berdi'}, status=status.HTTP_400_BAD_REQUEST)

# 12. Validate for expected data types using an "allow" list rather than a "deny" list.
# 12. Kutilayotgan ma'lumotlar turlarini "rad etish" ro'yxatidan ko'ra "ruxsat berish" ro'yxatidan foydalanib tasdiqlang.

# from rest_framework import serializers
#
# class OrderSerializer(serializers.Serializer):
#     STATUS_CHOICES = ['active', 'inactive']  # Ruxsat berilgan statuslar
#
#     status = serializers.ChoiceField(choices=STATUS_CHOICES)  # ChoiceField ruxsat berilgan qiymatlarni qabul qiladi
#
#     def validate_status(self, value):
#         # "ruxsat berish" ro'yxatidan tashqari qiymatlar rad etiladi
#         if value not in self.STATUS_CHOICES:
#             raise serializers.ValidationError(f"Status {value} ruxsat berilmagan.")
#         return value

# 13. Validate data range.
# 13. Ma'lumotlar oralig'ini tasdiqlash.

# class AgeSerializer(serializers.Serializer):
#     age = serializers.IntegerField()
#
#     def validate_age(self, value):
#         if not (0 <= value <= 120):
#             raise serializers.ValidationError("Age must be between 0 and 120.")
#         return value
# 14. Validate data length.
# 14. Ma'lumotlar uzunligini tasdiqlang.

# class UsernameSerializer(serializers.Serializer):
#     username = serializers.CharField(min_length=3, max_length=30)

# 15. If any potentially hazardous input must be allowed, then implement additional controls.
# 15. Har qanday potentsial xavfli kirishga ruxsat berish kerak bo'lsa, qo'shimcha nazoratni amalga oshiring.
# XSS hujumlarining oldini olish:


# import bleach
# from rest_framework import serializers
#
# class CommentSerializer(serializers.Serializer):
#     comment_text = serializers.CharField()
#
#     def validate_comment_text(self, value):
#         # HTML va JavaScript kodlarini tozalash
#         cleaned_value = bleach.clean(value, tags=[], attributes=[], styles=[], strip=True)
#         return cleaned_value

# 16. If the standard validation routine cannot address some inputs, then use extra discrete checks.
# 16. Agar standart tekshirish tartibi ba'zi kiritishlarni hal qila olmasa, qo'shimcha diskret tekshiruvlardan foydalaning.
# Izoh : Murakkab ma'lumotlar uchun maxsus tekshiruvchilarni yozing.

# from django.core.validators import URLValidator
#
# class URLSerializer(serializers.Serializer):
#     url = serializers.CharField()
#
#     def validate_url(self, value):
#         validator = URLValidator()
#         try:
#             validator(value)
#         except ValidationError:
#             raise serializers.ValidationError("Invalid URL format.")
#         return value

# 17. Utilize canonicalization to address obfuscation attacks.
# 17. Noto'g'rilash hujumlarini hal qilish uchun kanoniklashtirishdan foydalaning.

# Kanoniklashtirish Nima?
# Kanoniklashtirish — bu foydalanuvchi kiritgan ma'lumotlarni soddalashtirish yoki normallashtirish jarayoni.
# Bu jarayon foydalanuvchi tomonidan kiritilgan turli formatlardagi
# ma'lumotlarni yagona, standart formatga keltiradi. Kanoniklashtirish xavfsizlik uchun muhim,
# chunki u kirish ma'lumotlaridagi turli shakl va kodlash usullari orqali
# amalga oshiriladigan hujumlarni oldini olishga yordam beradi.

# Tushuntirish : chalkashlik orqali tekshiruvlarni chetlab o'tishning oldini olish uchun kiritishni normallashtiring.
#
# import re
# from urllib.parse import urlparse, urlunparse
# from rest_framework import serializers
#
# class URLSerializer(serializers.Serializer):
#     url = serializers.CharField()
#
#     def validate_url(self, value):
#         # URLni normallashtirish (kanoniklashtirish)
#         parsed_url = urlparse(value)
#
#         # Protokolni va domen nomini pastki registrga o'zgartirish
#         scheme = parsed_url.scheme.lower()  # http yoki https
#         netloc = parsed_url.netloc.lower()  # Domenni kichik harflarga o'zgartirish
#
#         # Qayta yig'ilgan URL
#         normalized_url = urlunparse((
#             scheme,
#             netloc,
#             parsed_url.path,
#             parsed_url.params,
#             parsed_url.query,
#             parsed_url.fragment
#         ))
#
#         # URL formatini tekshirish
#         if not re.match(r'^https?://', normalized_url):
#             raise serializers.ValidationError("URL http yoki https bilan boshlanishi kerak.")
#
#         return normalized_url

# --------------------

# from urllib.parse import urlparse
#
# # Sample URL
# url = "https://www.example.com:8080/path/to/resource;params?key=value#section1"
#
# # Parsing the URL
# parsed_url = urlparse(url)
#
# # Displaying the parsed components
# print(parsed_url)

# -----------

# ParseResult(
#     scheme='https',
#     netloc='www.example.com:8080',
#     path='/path/to/resource',
#     params='params',
#     query='key=value',
#     fragment='section1'
# )

# =========== Output Encoding ============
# Chiqish kodlash

# 1. Conduct all output encoding on a trusted system (server side, not client side).
# 1. Barcha chiqish kodlashni ishonchli tizimda o'tkazing (mijoz tomonida emas, server tomonida).

# DRFda barcha ma'lumotlarni qayta ishlash va kodlash mijozga javob yuborishdan oldin
# server tomonida amalga oshirilishi kerak.

# from rest_framework import serializers
#
# class SafeDataSerializer(serializers.Serializer):
#     name = serializers.CharField()
#     description = serializers.CharField()
#
#     def to_representation(self, instance):
#         # Perform any necessary sanitization or encoding
#         data = super().to_representation(instance)
#         data['description'] = instance.description.encode('utf-8', 'ignore').decode('utf-8')  # Ensure encoding
#         return data

# 2. Utilize a standard, tested routine for each type of outbound encoding.
# 2. Chiquvchi kodlashning har bir turi uchun standart, sinovdan o'tgan tartibdan foydalaning.
# Kodlash uchun o'rnatilgan Python va Django funksiyalaridan foydalaning.

# <script>alert('XSS')</script>
# &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;

# from django.utils.html import escape
#
# class HtmlSafeSerializer(serializers.Serializer):
#     content = serializers.CharField()
#
#     def to_representation(self, instance):
#         data = super().to_representation(instance)
#         data['content'] = escape(instance.content)  # Escape HTML content
#         return data

# 3. Specify character sets, such as UTF-8, for all outputs.
# 3. Barcha chiqishlar uchun UTF-8 kabi belgilar to'plamini belgilang.

# Server sukut bo'yicha UTF-8 dan foydalanishga sozlanganligiga ishonch hosil qiling.
# DRF uchun UTF-8 odatda standart sozlama hisoblanadi.

# from rest_framework.response import Response
#
# def safe_view(request):
#     response_data = {"message": "Hello, World!"}
#     return Response(response_data, content_type='application/json; charset=utf-8')

# 4. Contextually output encode all data returned to the client from untrusted sources.
# 4. Ishonchsiz manbalardan mijozga qaytarilgan barcha ma'lumotlarni kontekstli tarzda kodlash.

# Ishonchsiz maʼlumotlar uchun HTML, JSON va hokazolarda qanday ishlatilishiga qarab kontekstli kodlang.

# Ishonchsiz manbalar:

# Foydalanuvchi kiritgan ma'lumotlar:
#
# Formadagi foydalanuvchi kiritgan matnlar, izohlar, sharhlar yoki boshqa kirishlar. Foydalanuvchilar bu kiritmalarni maqsadsiz va xavfli kodlar bilan yuborishi mumkin.
# Tashqi API yoki xizmatlardan olingan ma'lumotlar:
#
# Masalan, boshqa xizmatlardan olingan JSON yoki HTML formatidagi ma'lumotlar. Agar bu ma'lumotlar tasdiqlanmasa yoki filtrlansa, ular ijtimoiy muammo yoki xavfga olib kelishi mumkin.
# HTML, JavaScript yoki CSS kiritmalari:
#
# Xavfli JavaScript kodlari, CSS inline tarzda yoki boshqa tegishli HTML elementlari (masalan, <script>) bilan kiritilishi mumkin. Bularni to'g'ri kodlash yoki xavfsiz tarzda sanitatsiya qilish zarur.
# Ma'lumotlar bazasidan olingan va foydalanuvchiga yuborilgan ma'lumotlar:
#
# Agar ma'lumotlar bazasidagi yozuvlar foydalanuvchi tomonidan kiritilgan ma'lumotlardan iborat bo'lsa, ular xavfli kodlarni o'z ichiga olishi mumkin.
# Fayllar yoki boshqa manbalardan olingan ma'lumotlar:
#
# Yüklangan fayllar yoki boshqa tashqi manbalardan ma'lumotlar ham xavfsizlikka tahdid solishi mumkin.
# from django.utils.html import escape
#
# class ContextualSafeSerializer(serializers.Serializer):
#     user_comment = serializers.CharField()
#
#     def to_representation(self, instance):
#         data = super().to_representation(instance)
#         data['user_comment'] = escape(instance.user_comment)  # Encode for HTML output
#         return data

# 5. Ensure the output encoding is safe for all target systems.
# 5. Chiqish kodlash barcha maqsadli tizimlar uchun xavfsiz bo'lishini ta'minlang.
# Chiqish kodlash ma'lumotlar mijoz tomonidan qanday qayta ishlanishini hisobga olganligiga ishonch hosil qiling.

# import json
#
# class JsonSafeSerializer(serializers.Serializer):
#     user_input = serializers.CharField()
#
#     def to_representation(self, instance):
#         data = super().to_representation(instance)
#         data['user_input'] = json.dumps(instance.user_input)  # Encode for JSON output
#         return data


# 6. Contextually sanitize all output of untrusted data to queries for SQL, XML, and LDAP.
# 6. SQL, XML va LDAP uchun so'rovlar uchun ishonchsiz ma'lumotlarning barcha chiqishini kontekstli ravishda tozalang.
# SQL: Ma'lumotlarni tozalash va to'g'ridan-to'g'ri so'rovlardan qochish uchun ORM usullaridan foydalaning.

# from django.db import models
#
# class SafeQueryModel(models.Model):
#     name = models.CharField(max_length=100)
#
#     @classmethod
#     def safe_query(cls, input_data):
#         # Use ORM methods instead of raw SQL to avoid SQL injection
#         return cls.objects.filter(name=input_data)


# 7. Sanitize all output of untrusted data to operating system commands.
# 7. Ishonchsiz ma'lumotlarning barcha chiqishini operatsion tizim buyruqlariga sanitarizatsiya qiling.



# ============== Authentication and Password Management ===============

# Autentifikatsiya va parolni boshqarish

# 1. Require authentication for all pages and resources, except those specifically intended to be public.
# 1. Barcha sahifalar va manbalar uchun autentifikatsiyani talab qiling, maxsus ochiq bo'lishi uchun mo'ljallanganlardan tashqari.
# Foydalanuvchilardan har bir soʻrov uchun autentifikatsiya qilishni talab qilish uchun Djangoning oʻrnatilgan autentifikatsiya tizimidan foydalaning. Buni amalga oshirish uchun ruxsatlardan foydalanishingiz mumkin IsAuthenticated.
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.views import APIView
#
# class MySecureView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request):
#         # Your logic
#         return Response({"message": "Authenticated"})
# ----------------------
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def my_secure_view(request):
#     # Your logic
#     return Response({"message": "Authenticated"})

# 2. All authentication controls must be enforced on a trusted system.
# 2. Barcha autentifikatsiyani boshqarish vositalari ishonchli tizimda amalga oshirilishi kerak.
#
# DRF da xavfsiz autentifikatsiyani boshqarishni tasvirlash uchun oddiy misol:
#
# Token autentifikatsiyasidan foydalanish : Biz DRF dan foydalanamiz
# TokenAuthenticationva barcha autentifikatsiya mantig'i server tomonida ishlashiga ishonch hosil qilamiz.
#
# Ko'rinishlar va autentifikatsiya mantig'i : Biz foydalanuvchi hisob ma'lumotlari xavfsiz
# tarzda tekshiriladigan kirish ko'rinishini yaratamiz.

# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': [
#         'rest_framework.authentication.TokenAuthentication',
#     ],
#     'DEFAULT_PERMISSION_CLASSES': [
#         'rest_framework.permissions.IsAuthenticated',
#     ],
# }

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.authtoken.models import Token
# from django.contrib.auth import authenticate
# from django.contrib.auth.models import User
#
# class LoginView(APIView):
#     def post(self, request):
#         username = request.data.get("username")
#         password = request.data.get("password")
#
#         # Authenticate the user securely
#         user = authenticate(username=username, password=password)
#
#         if user:
#             # Generate or retrieve the token
#             token, created = Token.objects.get_or_create(user=user)
#             return Response({"token": token.key}, status=status.HTTP_200_OK)
#         else:
#             return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


# from rest_framework.decorators import api_view
# from rest_framework.permissions import IsAuthenticated
#
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def logout_view(request):
#     # Delete the user's token to log them out
#     request.user.auth_token.delete()
#     return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)

# ----------------
# pip install djangorestframework-simplejwt
# INSTALLED_APPS = [
#     # Other apps...
#     'rest_framework',
#     'rest_framework_simplejwt',
# ]
#
# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'rest_framework_simplejwt.authentication.JWTAuthentication',
#     ),
# }

# from django.urls import path
# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
#
# urlpatterns = [
#     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#     path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
#     # Other URLs...
# ]

# curl -X POST http://localhost:8000/api/token/ \
#   -H "Content-Type: application/json" \
#   -d '{"username": "your_username", "password": "your_password"}'

# tokens = generate_jwt_tokens(user)
#
# attrs = {**attrs, **tokens}
#
# from rest_framework_simplejwt.tokens import RefreshToken
#
#
# def generate_jwt_tokens(user):
#     refresh = RefreshToken.for_user(user)
#     return {
#         'refresh': str(refresh),
#         'access': str(refresh.access_token),
#     }
#

# {
#     "access": "new_access_token"
# }

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated
#
# class SecureView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request):
#         return Response({"message": "You are authenticated!"})

# 6. Tokenning amal qilish muddatini boshqarish
# Kirish tokenining amal qilish muddati : Kirish tokenlari qisqa muddatga ega
# (masalan, 5-15 daqiqa), tokenning buzilishi taʼsirini kamaytirish uchun.
# Tokenlarni yangilash : "Kirish tokenini yangilash" bo'limida ko'rsatilganidek,
# muddati tugagach, yangi kirish tokenini olish uchun yangilash tokenidan foydalaning.


# 3. Establish and utilize standard, tested, authentication services whenever possible.
# 3. Imkon qadar standart, sinovdan o'tgan, autentifikatsiya xizmatlarini o'rnating va foydalaning.

# simplejwt haqida ma'lumot

# 4. Use a centralized implementation for all authentication controls, including libraries that call external authentication services.
# 4. Barcha autentifikatsiyani boshqarish vositalari, jumladan tashqi autentifikatsiya xizmatlarini chaqiruvchi kutubxonalar uchun markazlashtirilgan dasturdan foydalaning.

# from rest_framework_simplejwt.views import TokenObtainPairView
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth.models import User
#
# class CustomLoginView(TokenObtainPairView):
#     def post(self, request, *args, **kwargs):
#         # Get the user credentials from the request
#         username = request.data.get("username")
#         password = request.data.get("password")
#
#         try:
#             user = User.objects.get(username=username)
#         except User.DoesNotExist:
#             return Response({"detail": "Invalid username or password"}, status=status.HTTP_400_BAD_REQUEST)
#
#         if not user.check_password(password):
#             return Response({"detail": "Invalid username or password"}, status=status.HTTP_400_BAD_REQUEST)
#
#         # If credentials are valid, generate JWT token
#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)
#         refresh_token = str(refresh)
#
#         return Response({
#             'access': access_token,
#             'refresh': refresh_token,
#             'username': user.username
#         })

# 5. Segregate authentication logic from the resource being requested and use redirection to and from the centralized authentication control.
# 5. Autentifikatsiya mantig'ini so'ralayotgan manbadan ajratib oling va markazlashtirilgan autentifikatsiya boshqaruviga va undan qayta yo'naltirishdan foydalaning.

# settings.py
# LOGIN_URL = '/auth/login/'

# from rest_framework_simplejwt.views import TokenObtainPairView
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth.models import User
#
# class CustomLoginView(TokenObtainPairView):
#     def post(self, request, *args, **kwargs):
#         # Get the user credentials from the request
#         username = request.data.get("username")
#         password = request.data.get("password")
#
#         try:
#             user = User.objects.get(username=username)
#         except User.DoesNotExist:
#             return Response({"detail": "Invalid username or password"}, status=status.HTTP_400_BAD_REQUEST)
#
#         if not user.check_password(password):
#             return Response({"detail": "Invalid username or password"}, status=status.HTTP_400_BAD_REQUEST)
#
#         # If credentials are valid, generate JWT token
#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)
#         refresh_token = str(refresh)
#
#         return Response({
#             'access': access_token,
#             'refresh': refresh_token,
#             'username': user.username
#         })

# 6. All authentication controls should fail securely.
# 6. Barcha autentifikatsiya boshqaruvlari xavfsiz tarzda ishlamay qolishi kerak.

# return Response({"detail": "Invalid username or password"}

# 7. All administrative and account management functions must be at least as secure as the primary authentication mechanism.
# 7. Barcha ma'muriy va hisoblarni boshqarish funktsiyalari hech
# bo'lmaganda birlamchi autentifikatsiya mexanizmi kabi xavfsiz bo'lishi kerak.

# from rest_framework.permissions import BasePermission
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework.decorators import api_view
#
# # Custom Permission Class for Staff Only Access
# class IsStaff(BasePermission):
#     def has_permission(self, request, view):
#         # Only allow access if the user is a staff member
#         return request.user and request.user.is_staff
#
# # Sample View requiring staff access
# class StaffOnlyView(APIView):
#     permission_classes = [IsStaff]
#
#     def get(self, request):
#         return Response({"message": "Welcome, staff member!"})

# from rest_framework.permissions import IsAdminUser
# from rest_framework.response import Response
# from rest_framework.views import APIView
#
# class AdminOnlyView(APIView):
#     permission_classes = [IsAdminUser]
#
#     def get(self, request):
#         return Response({"message": "Welcome, admin!"})

# -------------------

# from django.contrib.admin.views.decorators import staff_member_required
#
# @staff_member_required
# def admin_function(request):
#     # Admin-specific logic
#     pass


# 8. If your application manages a credential store, use cryptographically strong one-way salted hashes.
# 8. Agar ilovangiz hisob ma'lumotlari do'konini boshqarsa, kriptografik jihatdan kuchli bir tomonlama tuzlangan xeshlardan foydalaning.
# 9. Password hashing must be implemented on a trusted system (server side, not client side).
# 9. Parolni xeshlash ishonchli tizimda (mijoz tomonida emas, server tomonida) amalga oshirilishi kerak.
#
# def create(self, validated_data):
#     # Hash the password before saving the user
#     validated_data['password'] = make_password(validated_data['password'])
#     user = User.objects.create(**validated_data)

#     return user
# 10. Validate the authentication data only on completion of all data input.
# 10. Autentifikatsiya ma'lumotlarini faqat barcha ma'lumotlarni kiritish tugagandan so'ng tasdiqlang.

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .serializers import UserLoginSerializer
#
# class UserLoginView(APIView):
#     def post(self, request):
#         # Deserialize and validate the incoming data
#         serializer = UserLoginSerializer(data=request.data)
#         if serializer.is_valid():
#             # Successfully validated the data
#             return Response({"message": "Login successful"})
#         else:
#             # Return errors if validation fails
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 11. Authentication failure responses should not indicate which part of the authentication data was incorrect.
# 11. Autentifikatsiya xatosi javoblari autentifikatsiya ma'lumotlarining qaysi qismi noto'g'ri ekanligini ko'rsatmasligi kerak.

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.exceptions import AuthenticationFailed
# from .authentication import CustomAuthentication
#
# class UserLoginView(APIView):
#     authentication_classes = [CustomAuthentication]  # Use custom authentication class
#
#     def post(self, request):
#         # Assuming authentication already happened via CustomAuthentication
#         try:
#             # Here we would typically check for session tokens or JWT, but authentication
#             # has already been handled by CustomAuthentication.
#             return Response({"message": "Login successful"})
#         except AuthenticationFailed as e:
#             # Handle failed login attempt
#             return Response({"detail": str(e)}, status=status.HTTP_401_UNAUTHORIZED)

# 12. Utilize authentication for connections to external systems that involve sensitive information or functions.
# 12. Maxfiy ma'lumotlar yoki funktsiyalarni o'z ichiga olgan tashqi tizimlarga ulanish uchun autentifikatsiyadan foydalaning.

# 1)-qadam: API kalitini Django sozlamalarida saqlang

# settings.py
# import os
#
# EXTERNAL_API_KEY = os.getenv('EXTERNAL_API_KEY')  # The API key for external service

# 13. Authentication credentials for accessing services external to the application should be stored in a secure store.
# 13. Ilovadan tashqari xizmatlarga kirish uchun autentifikatsiya ma'lumotlari xavfsiz do'konda saqlanishi kerak.

# .env fayli
# API_KEY='your_api_key'
# CLIENT_ID='your_client_id'
# CLIENT_SECRET='your_client_secret'

# import requests
# from django.conf import settings
#
# # Xavfsiz saqlangan API kaliti
# api_key = settings.API_KEY
# client_id = settings.CLIENT_ID
# client_secret = settings.CLIENT_SECRET
#
# # Tashqi tizim URL manzili
# url = 'https://external-system.com/api/endpoint/'
#
# # So'rov yuborish
# response = requests.get(url, headers={'Authorization': f'Bearer {api_key}'})
#
# if response.status_code == 200:
#     print('Ma\'lumotlar muvaffaqiyatli olingan:')
#     print(response.json())
# else:
#     print(f'Xato: {response.status_code}')

# 14. Use only HTTP POST requests to transmit authentication credentials.
# 14. Autentifikatsiya hisob ma'lumotlarini uzatish uchun faqat HTTP POST so'rovlaridan foydalaning.
#
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework import status
# from django.contrib.auth import authenticate
# from .serializers import AuthenticationSerializer
# from rest_framework_simplejwt.tokens import RefreshToken
#
#
# class AuthenticateView(APIView):
#     def post(self, request):
#         # Serializer yordamida ma'lumotlarni tekshiramiz
#         serializer = AuthenticationSerializer(data=request.data)
#         if serializer.is_valid():
#             username = serializer.validated_data['username']
#             password = serializer.validated_data['password']
#
#             # Autentifikatsiya qilish
#             user = authenticate(username=username, password=password)
#
#             if user is None:
#                 raise AuthenticationFailed('Foydalanuvchi nomi yoki parol noto‘g‘ri')
#
#             # JWT token yaratish
#             refresh = RefreshToken.for_user(user)
#             access_token = str(refresh.access_token)
#
#             # Tokenni qaytarish
#             return Response({"access_token": access_token}, status=status.HTTP_200_OK)
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 15. Only send non-temporary passwords over an encrypted connection or as encrypted data.
# 15. Vaqtinchalik bo'lmagan parollarni faqat shifrlangan ulanish orqali yoki shifrlangan ma'lumotlar sifatida yuboring.
#


# settings.py

# DEBUG = False  # Ishlab chiqarish muhitida DEBUG ni o'chirish
#
# # Faqat HTTPS ulanishlar
# SECURE_SSL_REDIRECT = True  # HTTP so'rovlarini HTTPS ga yo'naltirish
# SESSION_COOKIE_SECURE = True  # Session cookie'larni faqat HTTPS orqali uzatish
# CSRF_COOKIE_SECURE = True  # CSRF cookie'larni faqat HTTPS orqali uzatish



# from rest_framework import serializers, status
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from django.contrib.auth.models import User
#
#
# class PasswordChangeSerializer(serializers.Serializer):
#     old_password = serializers.CharField(write_only=True)
#     new_password = serializers.CharField(write_only=True)
#
#     def validate_new_password(self, value):
#         # Parolning kuchliligini tekshirish (ixtiyoriy)
#         if len(value) < 8:
#             raise serializers.ValidationError("Parol kamida 8 ta belgidan iborat bo'lishi kerak.")
#         return value
#
#
# class ChangePasswordView(APIView):
#     def post(self, request):
#         serializer = PasswordChangeSerializer(data=request.data)
#         if serializer.is_valid():
#             user = request.user
#
#             # Eski parolni tekshirish
#             if not user.check_password(serializer.validated_data['old_password']):
#                 return Response({"detail": "Eski parol noto'g'ri."}, status=status.HTTP_400_BAD_REQUEST)
#
#             # Yangi parolni o'rnatish
#             user.set_password(serializer.validated_data['new_password'])
#             user.save()
#
#             return Response({"detail": "Parol muvaffaqiyatli o'zgartirildi."}, status=status.HTTP_200_OK)
#
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 16. Enforce password complexity requirements established by policy or regulation.
# 16. Siyosat yoki qoidalar bilan belgilangan parol murakkabligi talablarini bajarish.

# 17. Enforce password length requirements established by policy or regulation.
# 17. Siyosat yoki qoidalar bilan belgilangan parol uzunligi talablarini bajarish.
#
# import re
# from rest_framework import serializers
#
# class PasswordValidator:
#     def __init__(self, min_length=8):
#         self.min_length = min_length
#
#     def validate(self, password):
#         # Minimal uzunlikni tekshirish
#         if len(password) < self.min_length:
#             raise serializers.ValidationError(f"Parol kamida {self.min_length} ta belgidan iborat bo'lishi kerak.")
#
#         # Katta harfni tekshirish
#         if not any(char.isupper() for char in password):
#             raise serializers.ValidationError("Parolda kamida bitta katta harf bo'lishi kerak.")
#
#         # Kichik harfni tekshirish
#         if not any(char.islower() for char in password):
#             raise serializers.ValidationError("Parolda kamida bitta kichik harf bo'lishi kerak.")
#
#         # Raqamni tekshirish
#         if not any(char.isdigit() for char in password):
#             raise serializers.ValidationError("Parolda kamida bitta raqam bo'lishi kerak.")
#
#         # Maxsus belgi (masalan, @, #, $, va h.k.) ni tekshirish
#         if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
#             raise serializers.ValidationError("Parolda kamida bitta maxsus belgi bo'lishi kerak.")
#
#         return password

# 18. Password entry should be obscured on the user's screen.
# 18. Parolni kiritish foydalanuvchi ekranida yashirin bo'lishi kerak.

# Frontend ilovasi: Shakllarda inputturdan foydalaning.password


# 19. Enforce account disabling after an established number of invalid login attempts.
# 19. Belgilangan miqdordagi noto'g'ri kirish urinishlaridan keyin hisob qaydnomasini o'chirib qo'yish.

# from django.contrib.auth.models import AbstractUser
# from django.db import models
#
# class CustomUser(AbstractUser):
#     failed_attempts = models.PositiveIntegerField(default=0)
#     is_disabled = models.BooleanField(default=False)
#
# from django.contrib.auth import authenticate
# from django.contrib.auth.models import update_last_login
# from django.core.exceptions import ValidationError
# from django.utils.translation import gettext_lazy as _
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import CustomUser
#
# MAX_ATTEMPTS = 5  # Set your preferred maximum attempt limit
#
# class LoginView(APIView):
#     def post(self, request, *args, **kwargs):
#         username = request.data.get("username")
#         password = request.data.get("password")
#         user = CustomUser.objects.filter(username=username).first()
#
#         if user:
#             if user.is_disabled:
#                 return Response(
#                     {"error": _("Account is disabled due to too many failed login attempts.")},
#                     status=status.HTTP_403_FORBIDDEN
#                 )
#
#             authenticated_user = authenticate(username=username, password=password)
#             if authenticated_user:
#                 # Reset failed attempts on successful login
#                 user.failed_attempts = 0
#                 user.save()
#                 update_last_login(None, user)
#                 return Response({"message": _("Login successful!")}, status=status.HTTP_200_OK)
#             else:
#                 # Increment failed attempts on unsuccessful login
#                 user.failed_attempts += 1
#                 if user.failed_attempts >= MAX_ATTEMPTS:
#                     user.is_disabled = True
#                 user.save()
#                 return Response(
#                     {"error": _("Invalid credentials. Please try again.")},
#                     status=status.HTTP_401_UNAUTHORIZED
#                 )
#         else:
#             return Response(
#                 {"error": _("User not found.")},
#                 status=status.HTTP_404_NOT_FOUND
#             )


# 20. Password reset and changing operations require the same level of controls as account creation and authentication.
# 20. Parolni qayta o'rnatish va o'zgartirish operatsiyalari hisob qaydnomasini yaratish va autentifikatsiya qilish bilan bir xil darajadagi nazoratni talab qiladi.

# from rest_framework import serializers
# from django.contrib.auth.models import User
# from django.utils.crypto import get_random_string
# from django.core.mail import send_mail
# from django.utils import timezone
# from datetime import timedelta
#
#
# class PasswordResetRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#
#     def validate_email(self, value):
#         if not User.objects.filter(email=value).exists():
#             raise serializers.ValidationError("User with this email does not exist.")
#         return value
#
#     def save(self):
#         email = self.validated_data['email']
#         user = User.objects.get(email=email)
#         reset_code = get_random_string(length=6, allowed_chars='0123456789')
#
#         # Store the reset code and the expiration time in the user's profile or a separate model
#         user.profile.reset_code = reset_code
#         user.profile.reset_code_expiration = timezone.now() + timedelta(minutes=10)
#         user.profile.save()
#
#         # Send the reset code via email
#         send_mail(
#             'Password Reset Code',
#             f'Your password reset code is: {reset_code}',
#             'from@example.com',
#             [email],
#             fail_silently=False,
#         )
#         return {"message": "Password reset code sent."}
#
# from rest_framework import serializers
# from django.contrib.auth.models import User
# from django.utils import timezone
#
# class PasswordResetWithCodeSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     code = serializers.CharField(max_length=6)
#     new_password = serializers.CharField(write_only=True)
#     confirm_password = serializers.CharField(write_only=True)
#
#     def validate(self, data):
#         if data['new_password'] != data['confirm_password']:
#             raise serializers.ValidationError("Passwords do not match.")
#         return data
#
#     def validate_code(self, value):
#         email = self.initial_data['email']
#         user = User.objects.get(email=email)
#         profile = user.profile
#
#         if profile.reset_code != value:
#             raise serializers.ValidationError("Invalid reset code.")
#         if timezone.now() > profile.reset_code_expiration:
#             raise serializers.ValidationError("Reset code has expired.")
#         return value
#
#     def save(self):
#         email = self.validated_data['email']
#         user = User.objects.get(email=email)
#         user.set_password(self.validated_data['new_password'])
#         user.profile.reset_code = None  # Clear the reset code
#         user.profile.reset_code_expiration = None
#         user.profile.save()
#         user.save()

# 21. Password reset questions should support sufficiently random answers.
# 21. Parolni tiklash savollari yetarlicha tasodifiy javoblarni qo'llab-quvvatlashi kerak.


# 22. If using email-based resets, only send email to a pre-registered address with a temporary link/password.
# 22. Agar elektron pochtaga asoslangan resetlardan foydalansangiz,
# faqat vaqtinchalik havola/parol bilan oldindan ro'yxatdan o'tgan manzilga elektron pochta xabarini yuboring.

# from rest_framework import serializers
# from django.contrib.auth.models import User
#
# class PasswordResetRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#
#     def validate_email(self, value):
#         if not User.objects.filter(email=value).exists():
#             raise serializers.ValidationError("Email address is not registered.")
#         return value
#
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth.models import User
# from django.core.mail import send_mail
# from django.utils.http import urlsafe_base64_encode
# from django.utils.encoding import force_bytes
# from django.contrib.auth.tokens import default_token_generator
# from django.urls import reverse
#
#
# class PasswordResetRequestView(APIView):
#     def post(self, request):
#         serializer = PasswordResetRequestSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             user = User.objects.get(email=email)
#
#             # Generate password reset token
#             token = default_token_generator.make_token(user)
#             uid = urlsafe_base64_encode(force_bytes(user.pk))
#             reset_link = request.build_absolute_uri(
#                 reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
#             )
#
#             # Send the email
#             send_mail(
#                 subject="Password Reset Request",
#                 message=f"Click the link to reset your password: {reset_link}",
#                 from_email="noreply@example.com",
#                 recipient_list=[email],
#                 fail_silently=False,
#             )
#             return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# from django.urls import path
# from .views import PasswordResetRequestView
#
# urlpatterns = [
#     path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
#     # Add a URL pattern for 'password_reset_confirm' in your project
# ]
# http://yourdomain.com/password-reset-confirm/<uidb64>/<token>/
#

# 23. Temporary passwords and links should have a short expiration time.
# 23. Vaqtinchalik parollar va havolalarning amal qilish muddati qisqa bo'lishi kerak.
# from django.db import models
# from django.contrib.auth.models import User
# from django.utils import timezone
# from datetime import timedelta
#
# class VerificationCode(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     code = models.CharField(max_length=4)
#     created_at = models.DateTimeField(auto_now_add=True)
#     expires_at = models.DateTimeField()
#
#     def is_expired(self):
#         return timezone.now() > self.expires_at
#
#     def save(self, *args, **kwargs):
#         # Set expiration time to 1 minute from creation
#         if not self.expires_at:
#             self.expires_at = timezone.now() + timedelta(minutes=1)
#         super().save(*args, **kwargs)
# ---
# from rest_framework import serializers
# from .models import VerificationCode
# import random
#
#
# class VerificationCodeSerializer(serializers.Serializer):
#     user_id = serializers.IntegerField()
#     code = serializers.CharField(read_only=True)
#
#     def generate_code(self):
#         """Generate a 4-digit random code."""
#         return str(random.randint(1000, 9999))
#
#     def validate(self, data):
#         user = User.objects.get(id=data['user_id'])
#         code = self.generate_code()
#
#         # Create and save the verification code
#         verification_code = VerificationCode.objects.create(
#             user=user,
#             code=code
#         )
#
#         # Return the code to the response (it would typically be sent to the user)
#         data['code'] = verification_code.code
#         return data
# ---
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .serializers import VerificationCodeSerializer
#
# class SendVerificationCodeView(APIView):
#     def post(self, request):
#         serializer = VerificationCodeSerializer(data=request.data)
#         if serializer.is_valid():
#             # In a real-world scenario, you would send the code to the user via SMS or email here.
#             return Response({"message": "Verification code sent", "code": serializer.validated_data['code']}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# ---
#
#
# class VerifyCodeSerializer(serializers.Serializer):
#     user_id = serializers.IntegerField()
#     code = serializers.CharField()
#
#     def validate(self, data):
#         user = User.objects.get(id=data['user_id'])
#         code = data['code']
#
#         try:
#             verification_code = VerificationCode.objects.get(user=user, code=code)
#         except VerificationCode.DoesNotExist:
#             raise serializers.ValidationError("Invalid code.")
#
#         # Check if the code is expired
#         if verification_code.is_expired():
#             raise serializers.ValidationError("The code has expired.")
#
#         return data

# 24. Enforce the changing of temporary passwords on the next use.
# 24. Keyingi foydalanishda vaqtinchalik parollarni o'zgartirishga majbur qiling.
#
# class CustomUser(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     is_temporary_password = models.BooleanField(default=False)
# ---
# from rest_framework import serializers
# from django.contrib.auth import authenticate
# from .models import CustomUser
#
# class PasswordChangeSerializer(serializers.Serializer):
#     old_password = serializers.CharField(write_only=True)
#     new_password = serializers.CharField(write_only=True)
#
#     def validate_old_password(self, value):
#         user = self.context['request'].user
#         if user.is_temporary_password:
#             raise serializers.ValidationError("You must change your temporary password.")
#         return value
#
#     def validate_new_password(self, value):
#         if len(value) < 8:
#             raise serializers.ValidationError("Password must be at least 8 characters.")
#         return value
#
#     def save(self):
#         user = self.context['request'].user
#         new_password = self.validated_data['new_password']
#         user.set_password(new_password)
#         user.is_temporary_password = False  # Update the flag after password change
#         user.save()
# ---
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated
# from rest_framework import status
# from .serializers import PasswordChangeSerializer
#
# class ChangePasswordView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def post(self, request):
#         serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"detail": "Password updated successfully."}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# ---
# from django.urls import path
# from .views import ChangePasswordView
#
# urlpatterns = [
#     path('change-password/', ChangePasswordView.as_view(), name='change-password'),
# ]
# ---
# from rest_framework_simplejwt.views import TokenObtainPairView
# from rest_framework.response import Response
#
# class CustomTokenObtainPairView(TokenObtainPairView):
#     def post(self, request, *args, **kwargs):
#         response = super().post(request, *args, **kwargs)
#         user = request.user
#         if user.is_temporary_password:
#             return Response({
#                 "detail": "You are using a temporary password. Please change it."
#             }, status=status.HTTP_400_BAD_REQUEST)
#         return response
# ---
# from django.urls import path
# from .views import CustomTokenObtainPairView
#
# urlpatterns = [
#     path('login/', CustomTokenObtainPairView.as_view(), name='login'),
# ]
# ---

# 25. Notify users when a password reset occurs.
# 25. Parolni tiklash sodir bo'lganda foydalanuvchilarni xabardor qiling.
#
# from django.core.mail import send_mail
# from django.contrib.auth.models import User
# from django.conf import settings
#
# def send_password_reset_notification(user):
#     subject = 'Parolingizni tiklash'
#     message = f"Salom {user.username},\n\nParolingizni tiklash uchun quyidagi havolani bosing:\n\n{settings.SITE_URL}/password_reset/\n\nAgar siz parolni tiklashni so'ramagan bo'lsangiz, iltimos, bu emailni e'tiborsiz qoldiring."
#     from_email = settings.DEFAULT_FROM_EMAIL
#     send_mail(subject, message, from_email, [user.email])
# # settings.py
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST = 'smtp.your-email-provider.com'
# EMAIL_PORT = 587
# EMAIL_USE_TLS = True
# EMAIL_HOST_USER = 'your-email@example.com'
# EMAIL_HOST_PASSWORD = 'your-email-password'
# DEFAULT_FROM_EMAIL = 'your-email@example.com'
# SITE_URL = 'http://yourwebsite.com'

# 26. Prevent password re-use.
# 26. Parolni qayta ishlatishni oldini olish.
# 24 da yozilgan


# 27. Passwords should be at least one day old before they can be changed, to prevent attacks on password re-use.
# 27. Parolni qayta ishlatish hujumlarining oldini olish uchun parollar o'zgartirilishidan oldin kamida bir kunlik eski bo'lishi kerak.
#
# from django.contrib.auth.models import AbstractUser
# from django.db import models
# from django.utils import timezone
#
# class CustomUser(AbstractUser):
#     password_changed_at = models.DateTimeField(null=True, blank=True)
#
#     def set_password(self, raw_password):
#         super().set_password(raw_password)
#         self.password_changed_at = timezone.now()
#         self.save()
# from django.utils import timezone
# from rest_framework import serializers
# from datetime import timedelta
# from django.contrib.auth import get_user_model
#
# User = get_user_model()
#
# class PasswordChangeSerializer(serializers.Serializer):
#     old_password = serializers.CharField(write_only=True)
#     new_password = serializers.CharField(write_only=True)
#
#     def validate_old_password(self, value):
#         user = self.context['request'].user
#         if not user.check_password(value):
#             raise serializers.ValidationError("Old password is incorrect.")
#         return value
#
#     def validate(self, data):
#         user = self.context['request'].user
#         if user.password_changed_at:
#             time_since_last_change = timezone.now() - user.password_changed_at
#             if time_since_last_change < timedelta(days=1):
#                 raise serializers.ValidationError("Password can only be changed once every 24 hours.")
#         return data
#
#     def save(self):
#         user = self.context['request'].user
#         user.set_password(self.validated_data['new_password'])
#         user.save()


# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status, permissions
#
# class PasswordChangeView(APIView):
#     permission_classes = [permissions.IsAuthenticated]
#
#     def post(self, request):
#         serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#
# 28. Enforce password changes based on requirements established in policy or regulation, with the time between resets administratively controlled.
# 28. Qayta o'rnatishlar orasidagi vaqt ma'muriy nazorat ostida bo'lgan holda, siyosat yoki qoidalarda belgilangan talablar asosida parol o'zgarishlarini amalga oshirish.

# 27 dayozilgan

# 29. Disable "remember me" functionality for password fields.
# 29. Parol maydonlari uchun "meni eslab qolish" funksiyasini o'chiring.

# settings.py

# Foydalanuvchi brauzerni yopganda seans tugashiga ishonch hosil qiling
# SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Seansning qisqa vaqtini o'rnating (masalan, 30 daqiqa)
# SESSION_COOKIE_AGE = 30 * 60

# Seans xavfsiz ekanligiga ishonch hosil qiling
# SESSION_COOKIE_SECURE = True  # Agar saytingiz HTTPS orqali taqdim etilsa, bundan foydalaning


# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status, permissions
# from django.contrib.auth import authenticate, login
#
# class LoginView(APIView):
#     permission_classes = [permissions.AllowAny]
#
#     def post(self, request):
#         username = request.data.get('username')
#         password = request.data.get('password')
#
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             request.session.set_expiry(0)  # Session will expire when the browser is closed
#             return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
#         else:
#             return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)




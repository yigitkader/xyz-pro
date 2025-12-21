Daha Fazla Performans İçin Öneriler
Shader seviyesinde optimizasyon gerekiyor:
GLV endomorphism kullanarak EC multiplication hızlandırma
Sliding window veya NAF (Non-Adjacent Form) kullanma
mod_inv yerine Jacobian coordiantes tutarak batch sonunda tek inversion
Bu değişiklikler shader'da kapsamlı refactor gerektirir. Mevcut durumda kod stabil ve doğru çalışıyor - performans GPU shader'ın intrinsic hızıyla sınırlı.
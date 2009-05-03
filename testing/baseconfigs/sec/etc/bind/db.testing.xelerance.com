;
; BIND data file for testing.xelerance.com domain
;
$TTL	604800
@	IN	SOA	freeswan.org. root.freeswan.org. (
			      5		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
		IN	NS	nic.testing.xelerance.com.
;
japan.testing.xelerance.com.		IN	A	192.0.1.2
sunset.testing.xelerance.com.	IN	A	192.0.1.1
west-private.testing.xelerance.com.	IN	A	192.0.1.254
west.testing.xelerance.com.		IN	A	192.1.2.45
			        IN      KEY     0x4200 4 1 AQNzGEFs18VKT00sA+4p+GUKn9C55PYuPQca6C+9Qhj0jfMdQnTRTDLeI+lp9TnidHH7fVpq+PkfiF2LHlZtDwMurLlwzbNOghlEYKfQ080WlOTTUAmOLhAzH28MF70q3hzq0m5fCaVZWtxcV+LfHWdxceCkjBUSaTFtR2W12urFCBz+SB3+OM33aeIbfHxmck2yzhJ8xyMods5kF3ek/RZlFvgN8VqBdcFVrZwTh0mXDCGN12HNFixL6FzQ1jQKerKBbjb0m/IPqugvpVPWVIUajUpLMEmi1FAXc1mFZE9x1SFuSr0NzYIu2ZaHfvsAZY5oN+I+R2oC67fUCjgxY+t7
nic.testing.xelerance.com.		IN	A	192.1.2.254
east.testing.xelerance.com.		IN	A	192.1.2.23
			        IN      KEY     0x4200 4 1 AQN3cn11FrBVbZhWGwRnFDAf8O9FHBmBIyIvmvt0kfkI2UGDDq8k+vYgRkwBZDviLd1p3SkL30LzuV0rqG3vBriqaAUUGoCQ0UMgsuX+k01bROLsqGB1QNXYvYiPLsnoDhKd2Gx9MUMHEjwwEZeyskMT5k91jvoAZvdEkg+9h7urbJ+kRQ4e+IHkMUrreDGwGVptV/hYQVCD54RZep6xp5ymaKRCDgMpzWvlzO80fP7JDjSZf9LI/MMu6c+qwXIKnWoNha75IhFyLWniVczxK2RdhmMhLsi0kC0CoOwWDSIEOb+5zbECDjjud+SF5tT8qRCWnSomX8jtbCdZ50WraQlL
east-private.testing.xelerance.com.	IN	A	192.0.2.254
sunrise.testing.xelerance.com.	IN	A	192.0.2.1
sunrise-oe.testing.xelerance.com.	IN	A	192.0.2.2

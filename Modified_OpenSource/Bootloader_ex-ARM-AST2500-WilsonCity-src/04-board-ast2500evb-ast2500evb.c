--- uboot.old/board/ast2500evb/ast2500evb.c	2020-06-01 14:15:22.287481443 -0400
+++ uboot/board/ast2500evb/ast2500evb.c	2020-06-01 14:29:02.433921250 -0400
@@ -279,6 +279,7 @@
 
 }
 #endif
+#define ESPI_STRAP              BIT(25)
 int board_init (void)
 {
     
@@ -294,7 +295,13 @@
 	
 #if defined(CONFIG_EARLYBOOT_ESPI_HANDSHAKE) 
 	
-	eSPI_config_handshake();
+	u32 strap;    
+	strap = readl(AST_SCU_BASE + 0x70);
+	printf("eSPI strap value 0x%x \n", strap);
+	if (strap & ESPI_STRAP)	
+	{
+		eSPI_config_handshake();
+	}
 	printf("eSPI Handshake complete\r\n");
 #endif
 
@@ -363,7 +370,7 @@
 	*(volatile u32 *)(AST_SCU_BASE + 0x180) &= ~(0x100);
 
 	*(volatile u32 *)(0x1e6e2080) &= 0xFF00FFFF; /* Disable UART3, configure GPIO */
-	*(volatile u32 *)(0x1e6e2070) |= 0x02400000; /* Enable GPIOE Passthrough and eSPI mode */
+	*(volatile u32 *)(0x1e6e2070) |= 0x00400000; /* Enable GPIOE Passthrough and eSPI mode */
 
 	*(volatile u32 *)(0x1e6e2004) &= ~(0x200); // Clear reset PWM controller
 	

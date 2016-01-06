# SPFBL_Spamassassin-Plugin
Módulo para Spamassassin que implementa a checagem no serviço SPFBL

## ATENÇÂO: O módulo não está pronto para ser utilizado em produção, utilize-o com cuidado!

# TODO:
* Melhorar o código (Eu sei ta feio).
* Adicionar o cabeçalho Received-SPFBL ao invés do X-Spam-Received-SPFBL (Ainda não descobri como tirar o prefixo dos headers).
* Implementar a configuração de pontuação através de configuração e não direto no código.
* O Spamassassin envia para o plugin os cabeçalhos conforme está no email, teria que fazer uma checagem para verificar qual dos destinatários será realmente o que será entregue a mensagem, por exemplo hoje se o to chegarda seguinte forma:  

To: fulano@example.com.br, asdas@meuprovedor.com.br

Ele vai analisar o "To" como sendo fulano@example.com.br e não o asdas@meuprovedor.com.br que seria o real destinatário da mensagem, portanto a verificação no SPFBL seria errada e o resultado não seria o esperado.

* O Spamassassin checa tanto as mensagens enviadas como recebidas, teria que verificar alguma forma de identificar se o email é sainte ou entrante. Se for sainte, executar a verificação junto ao SPFBL.

# Considerações
* Eu não manjo de perl então se você identificou algum erro sinta-se livre para contribuir!

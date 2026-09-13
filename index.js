require('dotenv').config();
const {
  Client,
  GatewayIntentBits,
  EmbedBuilder,
  SlashCommandBuilder,
  REST,
  Routes,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  PermissionFlagsBits,
  ChannelType
} = require('discord.js');
const axios = require('axios');
const FormData = require('form-data');
const express = require('express');

const VT_API_KEY = process.env.VT_API_KEY;
const VT_BASE = 'https://www.virustotal.com/api/v3';

// ---------- Configuración de canales ----------
// Canales donde TODOS los mensajes (de usuarios y del propio bot) se
// autodestruyen a los 2 minutos de haberse enviado.
const AUTO_DELETE_CHANNEL_IDS = ['1547651139254886400', '1546538254386335865'];
const AUTO_DELETE_DELAY_MS = 2 * 60 * 1000; // 2 minutos

// Único canal en el que el bot escanea automáticamente los archivos
// adjuntos que se suben en mensajes normales. El comando /scanurl sigue
// funcionando en cualquier canal.
const SCAN_FILE_CHANNEL_ID = '1547651139254886400';

// Programa el borrado de un mensaje si su canal está en la lista de
// autodestrucción. Silencioso si falla (p. ej. si ya fue borrado o si al
// bot le falta el permiso "Gestionar mensajes").
function programarAutoBorrado(message) {
  if (!message || !message.channelId) return;
  if (!AUTO_DELETE_CHANNEL_IDS.includes(message.channelId)) return;
  setTimeout(() => {
    message.delete().catch(() => {});
  }, AUTO_DELETE_DELAY_MS);
}

// ---------- Configuración del sistema de tickets ----------
// Opcionales: si no se configuran, los tickets se crean sin categoría y
// solo puede cerrarlos quien tenga el permiso "Gestionar canales" (además
// de la persona que abrió el ticket).
const TICKET_CATEGORY_ID = process.env.TICKET_CATEGORY_ID || '1546449940149047326';
const STAFF_ROLE_ID = process.env.STAFF_ROLE_ID || '1546539452388614236';
// Único rol autorizado a usar /clearchat.
const CLEARCHAT_ROLE_ID = process.env.CLEARCHAT_ROLE_ID || '1323439782155649028';

const TICKET_TYPES = {
  soporte: {
    panelChannelId: '1548737731524559018',
    prefix: 'ticket',
    label: 'Abrir ticket',
    emoji: '🎫',
    title: '🎫 Sistema de tickets',
    description: 'Si necesitás ayuda o tenés un problema, tocá el botón de abajo para abrir un ticket privado con el staff.',
    color: 0x2ecc71,
    bienvenida: 'Gracias por abrir un ticket. Contanos con detalle qué necesitás y el staff te va a responder a la brevedad.'
  },
  queja: {
    panelChannelId: '1548738432350552124',
    prefix: 'queja',
    label: 'Abrir queja/sugerencia',
    emoji: '📝',
    title: '📝 Quejas y sugerencias',
    description: 'Si tenés una queja o una sugerencia para mejorar el server, tocá el botón de abajo para abrir un canal privado con el staff.',
    color: 0xf1c40f,
    bienvenida: 'Gracias por tu queja/sugerencia. Contanos con detalle de qué se trata y el staff la va a revisar.'
  }
};

function esPersonalAutorizado(member) {
  if (!member) return false;
  if (member.permissions.has(PermissionFlagsBits.ManageChannels)) return true;
  if (STAFF_ROLE_ID && member.roles.cache.has(STAFF_ROLE_ID)) return true;
  return false;
}

// Publica el panel con botón en cada canal configurado, si todavía no existe
// (para no duplicarlo cada vez que el bot se reinicia).
async function asegurarPanelesDeTickets() {
  for (const [key, cfg] of Object.entries(TICKET_TYPES)) {
    try {
      const channel = await client.channels.fetch(cfg.panelChannelId);
      if (!channel) {
        console.error(`[TICKETS] No encontré el canal ${cfg.panelChannelId} para el panel de "${key}".`);
        continue;
      }

      const mensajes = await channel.messages.fetch({ limit: 20 });
      const yaExiste = mensajes.some(m => m.author.id === client.user.id && m.embeds[0]?.title === cfg.title);
      if (yaExiste) continue;

      const embed = new EmbedBuilder()
        .setTitle(cfg.title)
        .setDescription(cfg.description)
        .setColor(cfg.color);

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId(`open_ticket_${key}`)
          .setLabel(cfg.label)
          .setEmoji(cfg.emoji)
          .setStyle(ButtonStyle.Primary)
      );

      await channel.send({ embeds: [embed], components: [row] });
      console.log(`[TICKETS] Panel de "${key}" publicado en #${channel.name}`);
    } catch (err) {
      console.error(`[TICKETS] Error preparando el panel de "${key}":`, err.message);
    }
  }
}

async function abrirTicket(interaction, tipoKey) {
  const cfg = TICKET_TYPES[tipoKey];
  if (!cfg) return;

  await interaction.deferReply({ ephemeral: true });

  const guild = interaction.guild;
  const topicMarca = `ticket:${tipoKey}:${interaction.user.id}`;

  // Evitar que la misma persona abra dos tickets del mismo tipo a la vez.
  const existente = guild.channels.cache.find(c => c.topic === topicMarca);
  if (existente) {
    await interaction.editReply(`Ya tenés un ticket abierto: ${existente}`);
    return;
  }

  const overwrites = [
    { id: guild.roles.everyone.id, deny: [PermissionFlagsBits.ViewChannel] },
    {
      id: interaction.user.id,
      allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory]
    },
    {
      id: client.user.id,
      allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ManageChannels]
    }
  ];
  if (STAFF_ROLE_ID) {
    overwrites.push({
      id: STAFF_ROLE_ID,
      allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory]
    });
  }

  let canal;
  try {
    canal = await guild.channels.create({
      name: `${cfg.prefix}-${interaction.user.username}`.slice(0, 90),
      type: ChannelType.GuildText,
      parent: TICKET_CATEGORY_ID || undefined,
      topic: topicMarca,
      permissionOverwrites: overwrites
    });
  } catch (err) {
    console.error('[TICKETS] Error creando el canal:', err);
    await interaction.editReply('No pude crear el canal del ticket. Avisale a un admin (puede faltar el permiso "Gestionar canales" o estar mal el ID de la categoría).');
    return;
  }

  const embed = new EmbedBuilder()
    .setTitle(cfg.title)
    .setDescription(cfg.bienvenida)
    .setColor(cfg.color);

  const rowCerrar = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('close_ticket').setLabel('Cerrar ticket').setEmoji('🔒').setStyle(ButtonStyle.Danger)
  );

  await canal.send({ content: `${interaction.user}${STAFF_ROLE_ID ? ` <@&${STAFF_ROLE_ID}>` : ''}`, embeds: [embed], components: [rowCerrar] });
  await interaction.editReply(`Ticket creado: ${canal}`);
}

async function cerrarTicket(interaction) {
  const canal = interaction.channel;
  const esTicket = canal?.topic?.startsWith('ticket:');
  if (!esTicket) {
    await interaction.reply({ content: 'Esto no es un canal de ticket.', ephemeral: true });
    return;
  }

  const esDueño = canal.topic.endsWith(`:${interaction.user.id}`);
  if (!esDueño && !esPersonalAutorizado(interaction.member)) {
    await interaction.reply({ content: 'No tenés permiso para cerrar este ticket.', ephemeral: true });
    return;
  }

  await interaction.reply('🔒 Cerrando este ticket en 5 segundos...');
  setTimeout(() => {
    canal.delete().catch(() => {});
  }, 5000);
}

// Borra TODOS los mensajes de un canal. Discord solo permite el borrado
// masivo (bulkDelete) para mensajes de menos de 14 días; los más viejos
// hay que borrarlos uno por uno (más lento, con pausa para no chocar
// contra el rate limit de la API).
async function limpiarCanalCompleto(channel) {
  let totalBorrados = 0;

  while (true) {
    const mensajes = await channel.messages.fetch({ limit: 100 });
    if (mensajes.size === 0) break;

    let borrados;
    try {
      borrados = await channel.bulkDelete(mensajes, true); // true = ignora los de +14 días en vez de tirar error
    } catch (err) {
      console.error('[CLEARCHAT] Error en bulkDelete:', err.message);
      break;
    }
    totalBorrados += borrados.size;

    if (borrados.size < mensajes.size) {
      // Lo que quedó son mensajes de más de 14 días: solo se pueden borrar de a uno.
      const viejos = mensajes.filter(m => !borrados.has(m.id));
      for (const m of viejos.values()) {
        try {
          await m.delete();
          totalBorrados++;
          await new Promise(r => setTimeout(r, 1000));
        } catch (e) {}
      }
    }

    if (mensajes.size < 100) break; // ya no quedan más mensajes
  }

  return totalBorrados;
}

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
});

client.once('ready', async () => {
  console.log(`Conectado como ${client.user.tag}`);
  await asegurarPanelesDeTickets();
});

// ---------- Servidor web (necesario para Render + UptimeRobot) ----------
// Render "Web Service" exige que la app escuche un puerto HTTP, si no,
// lo marca como caído. UptimeRobot pinguea esta ruta cada X minutos
// para evitar que el free tier de Render duerma el servicio.
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Bot activo ✅');
});

app.listen(PORT, () => {
  console.log(`Servidor web escuchando en el puerto ${PORT}`);
});

// ---------- Registro de slash commands ----------
const commands = [
  new SlashCommandBuilder()
    .setName('scanurl')
    .setDescription('Analiza un link con VirusTotal')
    .addStringOption(opt => opt.setName('url').setDescription('El link a analizar').setRequired(true)),
  new SlashCommandBuilder()
    .setName('clearchat')
    .setDescription('Borra todos los mensajes de este canal (solo para el rol autorizado)'),
].map(c => c.toJSON());

const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
(async () => {
  try {
    await rest.put(Routes.applicationCommands(process.env.CLIENT_ID), { body: commands });
    console.log('Slash commands registrados');
  } catch (err) {
    console.error('Error registrando comandos:', err);
  }
})();

// ---------- Funciones VirusTotal ----------

async function scanUrl(url) {
  const form = new FormData();
  form.append('url', url);

  const submit = await axios.post(`${VT_BASE}/urls`, form, {
    headers: { ...form.getHeaders(), 'x-apikey': VT_API_KEY }
  });

  const analysisId = submit.data.data.id;
  return waitForAnalysis(analysisId);
}

async function scanFile(buffer, filename) {
  const form = new FormData();
  form.append('file', buffer, filename);

  const submit = await axios.post(`${VT_BASE}/files`, form, {
    headers: { ...form.getHeaders(), 'x-apikey': VT_API_KEY }
  });

  const analysisId = submit.data.data.id;
  return waitForAnalysis(analysisId);
}

// Espera a que termine el análisis (polling)
async function waitForAnalysis(analysisId) {
  for (let i = 0; i < 15; i++) {
    const res = await axios.get(`${VT_BASE}/analyses/${analysisId}`, {
      headers: { 'x-apikey': VT_API_KEY }
    });

    const status = res.data.data.attributes.status;
    if (status === 'completed') return res.data.data.attributes.results;

    await new Promise(r => setTimeout(r, 3000)); // espera 3s y reintenta
  }
  throw new Error('El análisis tardó demasiado en completarse');
}

// Convierte el resultado en un embed
function buildEmbed(target, results) {
  const engines = Object.values(results);
  const total = engines.length;
  const detected = engines.filter(e => e.category === 'malicious');
  const suspicious = engines.filter(e => e.category === 'suspicious');

  const ratio = total > 0 ? detected.length / total : 0;
  let veredicto = '✅ Limpio';
  if (detected.length > 0 && ratio < 0.1) veredicto = '⚠️ Posible falso positivo';
  else if (detected.length > 0) veredicto = '🚨 Malicioso';

  const embed = new EmbedBuilder()
    .setTitle('Resultado del análisis')
    .setDescription(`**Objetivo:** ${target}\n**Veredicto:** ${veredicto}`)
    .addFields(
      { name: 'Detecciones', value: `${detected.length} / ${total}`, inline: true },
      { name: 'Sospechosos', value: `${suspicious.length}`, inline: true }
    )
    .setColor(detected.length === 0 ? 0x2ecc71 : ratio < 0.1 ? 0xf1c40f : 0xe74c3c);

  if (detected.length > 0) {
    const detalle = detected
      .slice(0, 10)
      .map(e => `**${e.engine_name}**: ${e.result}`)
      .join('\n');
    embed.addFields({ name: 'Motores que detectaron algo', value: detalle });
  }

  return embed;
}

// ---------- Eventos ----------

client.on('interactionCreate', async interaction => {
  if (interaction.isChatInputCommand() && interaction.commandName === 'scanurl') {
    const url = interaction.options.getString('url');
    await interaction.deferReply();

    try {
      const results = await scanUrl(url);
      const embed = buildEmbed(url, results);
      await interaction.editReply({ embeds: [embed] });
    } catch (err) {
      await interaction.editReply(`Error al analizar: ${err.message}`);
    }

    try {
      const replyMsg = await interaction.fetchReply();
      programarAutoBorrado(replyMsg);
    } catch (e) {}
    return;
  }

  if (interaction.isChatInputCommand() && interaction.commandName === 'clearchat') {
    if (!interaction.member.roles.cache.has(CLEARCHAT_ROLE_ID)) {
      await interaction.reply({ content: '⛔ No tenés permiso para usar este comando.', ephemeral: true });
      return;
    }

    await interaction.deferReply({ ephemeral: true });
    const total = await limpiarCanalCompleto(interaction.channel);
    await interaction.editReply(`🧹 Listo, borré ${total} mensajes de este canal.`);
    return;
  }

  if (interaction.isButton()) {
    if (interaction.customId.startsWith('open_ticket_')) {
      const tipoKey = interaction.customId.replace('open_ticket_', '');
      await abrirTicket(interaction, tipoKey);
      return;
    }
    if (interaction.customId === 'close_ticket') {
      await cerrarTicket(interaction);
      return;
    }
  }
});

// Detectar archivos adjuntos en mensajes normales
client.on('messageCreate', async message => {
  // Autodestrucción: aplica a CUALQUIER mensaje (de usuario o del bot)
  // publicado en los canales configurados, tenga o no adjuntos.
  programarAutoBorrado(message);

  if (message.author.bot) return;
  if (message.attachments.size === 0) return;
  if (message.channelId !== SCAN_FILE_CHANNEL_ID) return; // el escaneo automático de archivos solo corre en este canal

  const attachment = message.attachments.first();
  const reply = await message.reply('🔍 Analizando archivo, esto puede tardar unos segundos...');
  programarAutoBorrado(reply);

  try {
    const fileRes = await axios.get(attachment.url, { responseType: 'arraybuffer' });
    const buffer = Buffer.from(fileRes.data);

    const results = await scanFile(buffer, attachment.name);
    const embed = buildEmbed(attachment.name, results);
    await reply.edit({ content: null, embeds: [embed] });
  } catch (err) {
    await reply.edit(`Error al analizar el archivo: ${err.message}`);
  }
});

client.login(process.env.DISCORD_TOKEN);
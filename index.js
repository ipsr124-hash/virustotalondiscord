require('dotenv').config();
const { Client, GatewayIntentBits, EmbedBuilder, SlashCommandBuilder, REST, Routes } = require('discord.js');
const axios = require('axios');
const FormData = require('form-data');
const express = require('express');

const VT_API_KEY = process.env.VT_API_KEY;
const VT_BASE = 'https://www.virustotal.com/api/v3';

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
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
  if (!interaction.isChatInputCommand()) return;

  if (interaction.commandName === 'scanurl') {
    const url = interaction.options.getString('url');
    await interaction.deferReply();

    try {
      const results = await scanUrl(url);
      const embed = buildEmbed(url, results);
      await interaction.editReply({ embeds: [embed] });
    } catch (err) {
      await interaction.editReply(`Error al analizar: ${err.message}`);
    }
  }
});

// Detectar archivos adjuntos en mensajes normales
client.on('messageCreate', async message => {
  if (message.author.bot) return;
  if (message.attachments.size === 0) return;

  const attachment = message.attachments.first();
  const reply = await message.reply('🔍 Analizando archivo, esto puede tardar unos segundos...');

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
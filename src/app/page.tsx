import React from "react";
import UnifiedSearch from "@/components/executive-osint/UnifiedSearch";

export default function Home() {
  return (
    <div className="min-h-screen bg-black text-white">
      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-500/20 rounded-lg">
                <Shield className="w-6 h-6 text-amber-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold">Executive Digital Protection</h1>
                <p className="text-sm text-gray-400">Unified OSINT Search Engine</p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm text-gray-400">
              <span className="flex items-center gap-1">
                <Search className="w-4 h-4" /> Google · Bing · Yandex · ipduh · etools
              </span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8">
        {/* Info Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {[{ type: "fullName", icon: "User", label: "Nombre Completo", desc: "Nombre y apellidos de la persona" },
           { type: "passport", icon: "Shield", label: "Pasaporte", desc: "Número de documento de viaje internacional" },
           { type: "nationalId", icon: "Hash", label: "Cédula/DNI", desc: "Documento de identidad nacional" },
           { type: "email", icon: "Mail", label: "Correo Electrónico", desc: "Dirección de email personal o corporativo" },
           { type: "phone", icon: "Phone", label: "Celular", desc: "Número de teléfono con código de país" },
           { type: "socialUrl", icon: "Globe", label: "Red Social", desc: "Perfil LinkedIn, Twitter, Facebook, etc." },
           { type: "alias", icon: "AtSign", label: "Alias/Nickname", desc: "Nombre de usuario en plataformas digitales" }].map(({ type, icon: Icon, label, desc }) => (
            <div key={type} className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-colors">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 bg-blue-500/20 rounded-lg">
                  <Icon className="w-5 h-5 text-blue-400" />
                </div>
                <h3 className="font-medium">{label}</h3>
              </div>
              <p className="text-sm text-gray-500">{desc}</p>
            </div>
          </div>
        </div>

        {/* Search Engine */}
        <UnifiedSearch />

        {/* Footer Info */}
        <div className="mt-12 pt-8 border-t border-gray-800">
          <h3 className="text-lg font-semibold mb-4">Cómo funciona</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm text-gray-400">
            <div className="space-y-2">
              <h4 className="font-medium text-white">1. Búsqueda Unificada</h4>
              <p>Consulta simultánea en 5 motores: Google, Bing, Yandex, ipduh.com y etools.ch</p>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium text-white">2. Coincidencia Exacta</h4>
              <p>Operadores de búsqueda avanzada para resultados precisos (" ", intext:, site:, filetype:)</p>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium text-white">3. Deduplicación Inteligente</h4>
              <p>Elimina duplicados entre motores y prioriza resultados con mayor confianza</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

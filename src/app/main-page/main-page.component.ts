import { Component } from '@angular/core';
import { MatButton } from '@angular/material/button';
import { AttestationService } from '../attestation.service';

@Component({
  selector: 'app-main-page',
  standalone: true,
  imports: [MatButton],
  templateUrl: './main-page.component.html',
  styleUrl: './main-page.component.css'
})
export class MainPageComponent {
  attestationResponse = '';

  constructor(private attestationService: AttestationService) {}

  async performAttestation() {
    this.attestationResponse = '';
    try{
    this.attestationResponse = await this.attestationService.performAttestation();
    } catch (e) {
      this.attestationResponse = `Exception: ${e}`;
    }
  }
}
